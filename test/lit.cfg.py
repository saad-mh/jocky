# lit configuration for the JOCKY test suite.
#
# Test files are `.jky` programs with `RUN:` / `CHECK:` lines in `//` comments,
# the same style LLVM uses. Run them with:
#   cmake --build build --target check

import os

import lit.formats

config.name = "JOCKY"

# Use lit's own small shell (not the system shell) so tests work the same on
# Windows without needing bash.
config.test_format = lit.formats.ShTest(execute_external=False)

config.suffixes = [".jky"]

# test_source_root / test_exec_root are set by the generated lit.site.cfg.py.

# Substitutions. Paths are quoted because they can contain spaces.
config.substitutions.append(("%jocky", '"{}"'.format(config.jocky_tool)))
config.substitutions.append(("%FileCheck", '"{}"'.format(config.filecheck_tool)))
config.substitutions.append(("%not", '"{}"'.format(config.not_tool)))

# Put the LLVM tools on PATH for the test subprocesses too (FileCheck, and later
# clang / llvm-objdump for the end-to-end tests).
_path_parts = [
    config.jocky_build_tools_dir,
    config.llvm_tools_dir,
    os.environ.get("PATH", ""),
]
config.environment["PATH"] = os.pathsep.join(p for p in _path_parts if p)

# Tests that compile and run a real executable declare `REQUIRES: e2e`.
if config.have_linker:
    config.available_features.add("e2e")
