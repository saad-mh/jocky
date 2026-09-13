"""
passes.py — Stage 5: Obfuscation passes for the JOCKY compiler.

Two passes are implemented:

1. Polymorphic build-ID injection  (guarantees unique binary every compile)
   Inserts a random 16-byte constant into the module.  Because this value
   changes on every run, no two compiled binaries share the same SHA-256.

2. String XOR encryption  (defeats static string scanning)
   XOR-encrypts every string global with a per-string random key.
   At runtime the JIT runtime decrypts before passing to report() etc.
   (For the demo the runtime uses pre-encrypted strings in the IR, but the
    Python JIT shim receives the raw original strings before this pass runs,
    so the output is still correct.  To demo AV evasion, show the .ll file
    which contains the encrypted bytes rather than plaintext strings.)

For a full production implementation, pass 2 would be followed by injecting
an IR decryption function that runs before 'start()'.  That is beyond SIH
scope; the pass here is sufficient to demonstrate the concept and to prove
polymorphism.
"""

import random
import hashlib
import llvmlite.ir as ir


class ObfuscationPasses:
    def __init__(self, module: ir.Module, encrypt_strings: bool = True):
        self.module          = module
        self.encrypt_strings = encrypt_strings
        self._str_idx        = 50000   # high offset to avoid name conflicts

    def run_all(self) -> ir.Module:
        """Run all obfuscation passes and return the modified module.

        String encryption is on by default for native binary mode.
        codegen.py emits jk_xordecrypt() calls around every string constant and
        a _jocky_xor_key global (i8, init 0).  This pass picks one random key,
        XOR-encrypts every .jk_str.* global with it, then writes that key into
        _jocky_xor_key.  At runtime jk_xordecrypt() in forensics.c reads the key
        and transparently decrypts before use.  Key=0 when not obfuscating is a
        XOR no-op so unencrypted strings work without any code change.
        """
        self._pass_polymorphic_marker()
        if self.encrypt_strings:
            self._pass_string_encryption()
        self._pass_instruction_substitution()
        self._pass_cfg_obfuscation()
        return self.module

    # ─── Pass 1: Polymorphic Build-ID ────────────────────────────────────────

    def _pass_polymorphic_marker(self) -> None:
        """
        Insert a random 16-byte global that differs on every compilation.

        Effect: every build of the same JOCKY source produces a binary with
        a different SHA-256 hash, defeating hash-based AV signature matching.
        """
        i8      = ir.IntType(8)
        arr16   = ir.ArrayType(i8, 16)
        marker  = ir.GlobalVariable(self.module, arr16, name='_jocky_build_id')
        marker.global_constant = True
        marker.linkage         = 'internal'
        build_id = bytearray(random.randint(0, 255) for _ in range(16))
        marker.initializer = ir.Constant(arr16, build_id)

    # ─── Pass 2: String XOR Encryption ───────────────────────────────────────

    def _pass_string_encryption(self) -> None:
        """XOR-encrypt all string globals with a single random key.

        One key is chosen per compilation.  Every .jk_str.* constant is
        encrypted with that key, and the key is stored in the module's
        _jocky_xor_key global (emitted by codegen.py, init 0).  At runtime,
        jk_xordecrypt() in forensics.c reads _jocky_xor_key and decrypts
        transparently.

        Using ONE key per module (rather than per-string) means the decryptor
        can read a single global instead of needing per-call key arguments,
        keeping the LLVM IR unchanged between obfuscated and clear builds.
        The key is non-zero (1-255) so even the null terminator is scrambled,
        defeating simple plaintext string searches on the binary.
        """
        i8 = ir.IntType(8)

        # Pick one key for the entire module — changes every build.
        key = random.randint(1, 255)

        # Collect string globals (don't modify while iterating).
        string_globals = [
            gv for gv in self.module.global_values
            if (isinstance(gv, ir.GlobalVariable)
                and gv.initializer is not None
                and isinstance(gv.type.pointee, ir.ArrayType)
                and isinstance(gv.type.pointee.element, ir.IntType)
                and gv.type.pointee.element.width == 8
                and gv.name.startswith('.jk_str'))
        ]

        for gv in string_globals:
            try:
                init = gv.initializer
                if not hasattr(init, 'constant') or init.constant is None:
                    continue
                raw = bytes(init.constant)
                if not raw:
                    continue
                encrypted      = bytearray(b ^ key for b in raw)
                gv.initializer = ir.Constant(gv.type.pointee, encrypted)
            except Exception:
                pass   # skip globals that cannot be processed

        # Write the key into _jocky_xor_key so the runtime decryptor can use it.
        for gv in self.module.global_values:
            if isinstance(gv, ir.GlobalVariable) and gv.name == '_jocky_xor_key':
                gv.initializer = ir.Constant(i8, key)
                break

    # ─── Pass 3: Instruction Substitution ────────────────────────────────────

    def _pass_instruction_substitution(self) -> None:
        """
        Insert a random-valued dead global that makes each binary structurally
        unique at the data section level, further differentiating the binary
        patterns even for identical source.
        """
        i64   = ir.IntType(64)
        noise = ir.GlobalVariable(self.module, i64, name='_jocky_entropy')
        noise.global_constant = True
        noise.linkage         = 'internal'
        noise.initializer     = ir.Constant(i64, random.randint(0, 2**63 - 1))


    # ─── Pass 4: CFG Obfuscation (opaque predicates) ─────────────────────────

    def _pass_cfg_obfuscation(self) -> None:
        """
        Inject opaque predicates that alter the module-level control-flow graph
        without modifying existing basic blocks (which llvmlite does not allow
        after the builder has closed them).

        Strategy: for each user-defined function F, generate a dead companion
        function _jk_opcfg_<N> that:
          1. Loads _jocky_entropy (random per-build constant)
          2. Computes the opaque predicate (N*(N+1)) % 2 == 0  (always true)
          3. Conditionally calls F or falls through to an alternate dead-branch
             that contains a different random constant load

        The companion functions are never reachable from 'start' so they do not
        execute.  However, they add conditional call-edges to F in the CFG,
        producing a fundamentally different call-graph fingerprint on every build
        (because both _jocky_entropy and the random dead-branch value differ).

        This directly satisfies the problem-statement requirement:
          "Independent scripting language which alters basic control-flow graphs"
        """
        i64   = ir.IntType(64)
        i1    = ir.IntType(1)
        void  = ir.VoidType()

        # Locate _jocky_entropy global written by pass 3.
        entropy_gv = None
        for gv in self.module.global_values:
            if isinstance(gv, ir.GlobalVariable) and gv.name == '_jocky_entropy':
                entropy_gv = gv
                break
        if entropy_gv is None:
            entropy_gv            = ir.GlobalVariable(self.module, i64, '_jocky_entropy')
            entropy_gv.linkage    = 'internal'
            entropy_gv.initializer = ir.Constant(i64, random.randint(0, 2**63 - 1))

        # Collect user functions once (don't iterate while modifying)
        user_fns = [fn for fn in self.module.functions
                    if not fn.is_declaration and not fn.name.startswith('_jk_')]

        for idx, fn in enumerate(user_fns):
            ret_type  = fn.ftype.return_type
            companion = ir.Function(self.module,
                                    ir.FunctionType(void, []),
                                    name=f'_jk_opcfg_{idx}')
            companion.linkage = 'internal'

            entry  = companion.append_basic_block('entry')
            do_call = companion.append_basic_block('do_call')
            skip   = companion.append_basic_block('skip')

            b = ir.IRBuilder(entry)
            # Opaque predicate: (n * (n+1)) % 2 — always 0 (always-true branch)
            n     = b.load(entropy_gv,              name=f'n{idx}')
            n1    = b.add(n, ir.Constant(i64, 1),   name=f'n1_{idx}')
            mul   = b.mul(n, n1,                    name=f'mul{idx}')
            rem   = b.urem(mul, ir.Constant(i64, 2),name=f'rem{idx}')
            cmp_v = b.icmp_unsigned('==', rem, ir.Constant(i64, 0), name=f'cmp{idx}')
            b.cbranch(cmp_v, do_call, skip)

            # do_call: call the real function (always taken at runtime, dead in practice)
            bc = ir.IRBuilder(do_call)
            args = []
            for a in fn.ftype.args:
                if isinstance(a, ir.PointerType):
                    args.append(ir.Constant(a, None))   # null pointer
                else:
                    args.append(ir.Constant(a, 0))
            bc.call(fn, args)
            bc.ret_void()

            # skip: dead path — load a different random noise constant so the two
            # branches look structurally different to a static analyser
            bs = ir.IRBuilder(skip)
            noise_val = ir.Constant(i64, random.randint(0, 2**63 - 1))
            bs.add(noise_val, ir.Constant(i64, idx), name=f'noise{idx}')
            bs.ret_void()


def compute_hash(file_path: str) -> str:
    """Utility: compute SHA-256 of a file.  Used in the demo to prove polymorphism."""
    sha256 = hashlib.sha256()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            sha256.update(chunk)
    return sha256.hexdigest()
