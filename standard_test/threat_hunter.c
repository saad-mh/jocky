/*
 * threat_hunter.c  —  Forensic Threat Hunter (Plain C Version)
 *
 * PURPOSE OF THIS FILE IN THE DEMO
 * =================================
 * This is the SAME forensic scanner written in plain C using standard
 * Windows APIs.  Windows Defender will flag or quarantine this binary
 * because:
 *
 *   1. STATIC STRINGS: Indicator strings like "mimikatz.exe",
 *      "meterpreter.exe", "procdump.exe" appear as plaintext in the
 *      binary — exactly matching AV YARA rules.
 *
 *   2. API HEURISTICS: The sequence
 *        CreateToolhelp32Snapshot → Process32Next → strcmp(name, "mimikatz")
 *      is a textbook process-scan heuristic that behavioural engines flag.
 *
 *   3. FIXED HASH: Every compile produces the exact same binary
 *      (deterministic input → deterministic output).  Once Defender has
 *      seen and flagged this hash, it is permanently blacklisted.
 *
 * Compare with threat_hunter.jk — identical logic, none of those three
 * properties.
 *
 * COMPILE (run from the JOCKY project root):
 *   gcc standard_test/threat_hunter.c -o standard_test/threat_hunter_c.exe \
 *       -lpsapi -ladvapi32 -O2 -mconsole
 *
 * RUN:
 *   standard_test\threat_hunter_c.exe
 *   (Defender will likely block/quarantine before it can run.)
 */

#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

/* ── Known threat-tool process names ──────────────────────────────────────── */
/* These plaintext strings in the binary are exactly what AV YARA rules scan  */
static const char* THREAT_PROCS[] = {
    "mimikatz.exe",       /* credential dumper       */
    "meterpreter.exe",    /* Metasploit payload      */
    "cobaltstrike.exe",   /* C2 framework            */
    "procdump.exe",       /* LSASS memory dumper     */
    "wce.exe",            /* Windows Credentials Ed. */
    "pwdump.exe",         /* password extractor      */
    "nc.exe",             /* netcat reverse shell    */
    "ncat.exe",           /* nmap netcat variant     */
    "psexec.exe",         /* lateral movement tool   */
    "lazagne.exe",        /* credential harvester    */
    NULL
};

/* ── Suspicious registry persistence paths ────────────────────────────────── */
static const char* PERSIST_KEYS[] = {
    "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
    "SYSTEM\\CurrentControlSet\\Services",
    NULL
};

/* ─────────────────────────────────────────────────────────────────────────── */

static void scan_processes(void)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        printf("[ERROR] CreateToolhelp32Snapshot failed (%lu)\n", GetLastError());
        return;
    }

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);

    printf("[SCAN] Enumerating running processes...\n");
    int alerts = 0;

    if (Process32First(snap, &pe)) {
        do {
            for (int i = 0; THREAT_PROCS[i] != NULL; i++) {
                if (_stricmp(pe.szExeFile, THREAT_PROCS[i]) == 0) {
                    printf("[ALERT] Threat tool detected: %-25s (PID %5lu)\n",
                           pe.szExeFile, pe.th32ProcessID);
                    alerts++;
                }
            }
        } while (Process32Next(snap, &pe));
    }

    CloseHandle(snap);

    if (alerts == 0)
        printf("[OK]   No known threat tools found in process list\n");
    else
        printf("[!!]   %d threat indicator(s) detected\n", alerts);
}

static void scan_registry(void)
{
    printf("\n[SCAN] Checking persistence registry locations...\n");

    for (int i = 0; PERSIST_KEYS[i] != NULL; i++) {
        HKEY hKey = NULL;
        LONG rc = RegOpenKeyExA(HKEY_LOCAL_MACHINE, PERSIST_KEYS[i],
                                0, KEY_READ, &hKey);
        if (rc == ERROR_SUCCESS) {
            /* Enumerate values — look for unsigned or suspicious entries */
            DWORD idx = 0;
            char  valName[256];
            DWORD valNameSz = sizeof(valName);
            DWORD valType;

            printf("[INFO] HKLM\\%s\n", PERSIST_KEYS[i]);

            while (RegEnumValueA(hKey, idx, valName, &valNameSz,
                                 NULL, &valType, NULL, NULL) == ERROR_SUCCESS) {
                printf("         value[%lu]: %s (type %lu)\n",
                       idx, valName, valType);
                idx++;
                valNameSz = sizeof(valName);
            }

            RegCloseKey(hKey);
        } else {
            printf("[SKIP] Cannot open HKLM\\%s (access denied or missing)\n",
                   PERSIST_KEYS[i]);
        }
    }
}

static void scan_network(void)
{
    printf("\n[SCAN] Network connection snapshot...\n");
    /* In a real tool: GetTcpTable2 / GetExtendedTcpTable                    */
    /* For demo purposes we note the intent without requiring iphlpapi.dll.  */
    printf("[INFO] (Full network scan requires -liphlpapi — stub for demo)\n");
}

int main(void)
{
    printf("============================================================\n");
    printf("  FORENSIC THREAT HUNTER  —  Plain C Version\n");
    printf("  (This binary is flagged by Windows Defender)\n");
    printf("============================================================\n\n");

    scan_processes();
    scan_registry();
    scan_network();

    printf("\n[DONE] Scan complete.\n");
    return 0;
}
