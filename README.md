
# EPA SWMM5 Computational Engine Global Buffer Overflow (CWE-787)

An out-of-bounds memory write vulnerability (Global Buffer Overflow) has been discovered in the EPA Stormwater Management Model (SWMM5) computational core solver architecture (affecting versions up to and including v5.2.4). The flaw resides within the solver's error logging subsystem, where unvalidated string compilation tokens are handled via unbounded memory copy routines. Processing a maliciously crafted configuration file (`.inp`) triggers a denial-of-service (DoS) condition via an immediate segmentation fault (`SIGSEGV`).

## 🔒 Vulnerability Metadata
* **Vulnerability Type:** Out-of-bounds Write / Global Buffer Overflow ([CWE-787](https://cwe.mitre.org/data/definitions/787.html))
* **Component Affected:** `src/solver/error.c` -> `error_setInpError()`
* **Vector Execution:** Local File Ingestion (`.inp` parsing configuration)
* **Impact:** Availability / Process Failure / Application Denial of Service (DoS)
* **Discovered By:** mit (pwnmit Security Research)

---

## 🔍 Technical Analysis & Root Cause

The SWMM5 parser architecture isolates spatial and physical input properties using strictly structured data allocations. However, a logical boundary check mismatch occurs during syntax exception handling when evaluating application configurations inside `src/solver/treatmnt.c`.

### 1. Data Aggregation and Validation Failure (`treatmnt.c`)

During treatment sequence evaluation, configuration arguments are read and concatenated up to the maximum permitted line bounds (`MAXLINE`):

```c
sstrncpy(s, tok[2], MAXLINE);
for (i = 3; i < ntoks; i++) {
    sstrcat(s, " ", MAXLINE);
    sstrcat(s, tok[i], MAXLINE);
}
...
else return error_setInpError(ERR_KEYWORD, tok[2]);

```

If keyword parsing constraints fail (e.g., structural character layouts violate validation markers), the engine immediately falls back to error propagation. It routes the raw, unvalidated configuration argument reference string (`tok[2]`) to the central logging sub-tier via `error_setInpError()`.

### 2. Unbounded Memory Ingestion (`error.c`)

The target exception logging module allocates a global tracking buffer, `ErrString`, with a fixed storage limit of `256` bytes in the uninitialized data segment (`.bss`):

```c
char  ErrString[256];
...
int  error_setInpError(int errcode, char* s)
{
    strcpy(ErrString, s); // Vulnerable Unbounded Memory Copy
    return errcode;
}

```
### 📊 Compilation Instrumentation & AddressSanitizer Logs

Compiling the engine executable with AddressSanitizer (ASan) tracking directives exposes the exact memory offset collision when the bug is triggered:
Plaintext
```
=================================================================
==3484==ERROR: AddressSanitizer: global-buffer-overflow on address 0x7f34a6df0fe0 at pc 0x7f34a6ea2681 bp 0x7ffdfa8c2a00 sp 0x7ffdfa8c21c0
WRITE of size 996 at 0x7f34a6df0fe0 thread T0
    #0 0x7f34a6ea2680 in strcpy ../../../../src/libsanitizer/asan/asan_interceptors.cpp:563
    #1 0x7f34a6c93452 in error_setInpError /src/solver/error.c:47
    #2 0x7f34a6d87b50 in treatmnt_readExpression /src/solver/treatmnt.c:134
    #3 0x7f34a6cc52af in parseLine /src/solver/input.c:596

0x7f34a6df0fe0 is located 0 bytes after global variable 'ErrString' defined in 'error.c:28:7' of size 256
SUMMARY: AddressSanitizer: global-buffer-overflow in strcpy
==3484==ABORTING
```
### 🔬 Proof of Concept Replication

The repository includes a standalone automated script (exploit.py) designed to dynamically generate the memory violation test criteria, spin up the verification loop, and inspect execution health metrics safely.
Step 1: Clone and Move to Binary Directory
Ensure your target executable environment (swmm5 or runswmm) is located in the local context directory.
Step 2: Set Execution Permissions

```
chmod +x exploit.py
```
Step 3: Launch Verification Wrapper
```
./exploit.py
```
(POC(https://github.com/pwnmit/EPA-SWMM5-Global-Buffer-Overflow/blob/main/SWMM_poc.png))
### 🔧 Mitigations & Code Fix

To resolve the memory boundary breach, the insecure strcpy() call must be replaced with strict length-restricted memory assignment functions.

Modify src/solver/error.c near Line 45 to utilize snprintf(), which caps character ingestion to the destination array bounds:
```
int  error_setInpError(int errcode, char* s)
{
    // Restrict string manipulation safely to the target structural array length
    snprintf(ErrString, sizeof(ErrString), "%s", s);
    return errcode;
}
```
