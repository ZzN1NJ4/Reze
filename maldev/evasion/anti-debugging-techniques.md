# Anti Debugging Techniques

More often than times your dumb executable will be flagged and obviously there would be times where you have to check the behavior of a weird executable. But there are enormous different ways a malware can identify its being debugged. I’ll discuss a few here,  then I’ll just keep updating the links to different methods at the end.

### 1. Read `BeingDebugged`&#x20;

This is the simplest of all. There is a `BeingDebugged` structure in `PEB` which we can read to check if we are being debugged or not. Its set to `0x00` by default but if a program is being debugged, then it will be updated to `0x01`.

Here’s a short program in rust to read what we want.

```rust
pub unsafe fn __readgsqword(diff: u32) -> i32 {
    let out: i32;
    asm!(
        "mov {}, gs:[{:e}]",
        lateout(reg) out,
        in(reg) diff,
        options(nostack, pure, readonly),
    );
    out
}

unsafe fn is_dbg(ppeb: usize) -> bool {
    let peb = ppeb as *const u8;
    *peb.offset(2) != 0
}

fn main() {
    unsafe {
        let peb = __readgsqword(OFFSET);
        println!("PEB: {:#x}", peb);
        
        let t = is_dbg(peb as usize);
        println!("Debugging: {}", t);

    }
}
```

Below is the screenshot of me running the same program from VSCode & x64dbg attached as well, we can see that the debugging is true in the case of x64dbg.

<figure><img src="../../.gitbook/assets/image (1) (1).png" alt=""><figcaption></figcaption></figure>

### 2. Hardware Breakpoint

Whenever a hardware breakpoint is set, any of the DR\[0-3] registers are updated. These are thread specific registers and we can read them using the `GetThreadContext`.

```rust
BOOL _chk_HardwareBreakpoint(HMODULE hNTDLL) {

    NtGetContextThread pNtGetContextThread = (NtGetContextThread)GetProcAddress(hNTDLL, "NtGetContextThread");
    CONTEXT Ctx = { .ContextFlags = CONTEXT_DEBUG_REGISTERS };
    NTSTATUS STATUS = pNtGetContextThread(CurrentThreadHandle, &Ctx);
    if (STATUS != STATUS_SUCCESS) {
        warn("ThreadCtx failed  @--0x%x", STATUS);
    }
    
    if (Ctx.Dr0 != NULL || Ctx.Dr1 != NULL || Ctx.Dr2 != NULL || Ctx.Dr3 != NULL) {
        info("Kernel Debugger attached");
        // do something
        return TRUE;
    }
    return FALSE;
}
```

There are a total of 6 DR registers, the ones in 0-3 are responsible for storing the address of the breakpoint. So basically for a single thread, there can only be 4 h/w breakpoints. I’ll talk about them in some other posts but for now this should suffice

* DR0-3 are responsible for storing the linear address of the breakpoint.
* DR4-5 are Reserved and generally point to DR6-7 respectively unless the Debug Extension is enabled
* DR6 stores the debug status. It contains bits to check if certain events were triggered
* DR7 is the control register, responsible for enabling & disabling the breakpoints

### 3. TLS Callback

Checking for the presence of a debugger in the **`main`** function is not the best idea, as this is the first place a reverser will look when viewing a disassembler listing. Checks implemented in **`main`** can be erased by **`NOP`** instructions thus disarming the protection. If the CRT library is used, the main thread will already have a certain call stack before transfer of control to the **`main`** function. Thus a good place to perform a debugger presence check is in the TLS Callback. Callback function will be called before the executable module entry point call. Although it will not save you against seasoned reversers, but it will weed out many schoolchildren who will not understand what happened.

```c
#pragma section(".CRT$XLY", long, read)
__declspec(thread) int var = 0xDEADBEEF;
VOID NTAnopPI TlsCallback(PVOID DllHandle, DWORD Reason, VOID Reserved)
{
    var = 0xB15BADB0; // Required for TLS Callback call
    if (IsDebuggerPresent())
    {
        MessageBoxA(NULL, "Stop debugging program!", "Error", MB_OK | MB_ICONERROR);
        TerminateProcess(GetCurrentProcess(), 0xBABEFACE);
    }
}
__declspec(allocate(".CRT$XLY"))PIMAGE_TLS_CALLBACK g_tlsCallback = TlsCallback;
```

There is a long explanation of the “.CRT$XLY”, I’ll talk about it in another post, for now its enough to know that this will run before entering the actual main function.

### 4. NtGlobalFlag

The `NtGlobalFlag` inside `PEB` is 0 by default. Attaching a debugger doesn’t change its value but if the process was created by a debugger, the following flags will be set:

* FLG\_HEAP\_ENABLE\_TAIL\_CHECK (0x10)
* FLG\_HEAP\_ENABLE\_FREE\_CHECK (0x20)
* FLG\_HEAP\_VALIDATE\_PARAMETERS (0x40)

```c
#define FLG_HEAP_ENABLE_TAIL_CHECK 0x10
#define FLG_HEAP_ENABLE_FREE_CHECK 0x20
#define FLG_HEAP_VALIDATE_PARAMETERS 0x40
#define FLG_NT_GLOBAL_DEBUG (FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS)

BOOL _chk_globalFlag() {
    PDWORD NtGlobalFlag = (PDWORD)(__readgsqword(0x60) + 0xBC);
    if ((*NtGlobalFlag) & FLG_NT_GLOBAL_DEBUG) {
        info("NtGlobalFlag  @--0x%p", *NtGlobalFlag);
        return TRUE;
    }
    return FALSE;
}
```

### 5. In-Circuit Exception (ICE / ICEBP)

Intel has an `ice` (0xF1) undocumented instruction which causes an EXCEPTION\_SINGLE\_STEP `(0x80000004`) when executed. The debugger considers this exception as the normal and generated by executing the instruction with the [SingleStep](https://en.wikipedia.org/wiki/Trap_flag#Single-step_interrupt) bit set in the Flags registers.

```c
BOOL _chk_icebp()
{
    __try
    { 
        __asm __emit 0xF1 
    }
    __except(EXCEPTION_EXECUTE_HANDLER) // EXCEPTION_EXECUTE_HANDLER = 1
    { 
        return FALSE; 
    }
    return TRUE;
}
```

### 6. Kernel Debugging

The `SystemKernelDebuggerInformation` (0x23) class returns the value of  `KdDebuggerEnabled` in `al` which is 0 by default unless the user allows for kernel debugging (through bcdedit,etc), and `KdDebuggerNotPresent` in `ah` which is 1 by default unless a kernel debugger is present.

```c
BOOL _chk_KernelDebugger(HANDLE hNTDLL) {

    SYSTEM_KERNEL_DEBUGGER_INFORMATION Sysinfo;
    NtQuerySystemInformation fNtQuerySystemInformation = (NtQuerySystemInformation)GetProcAddress(hNTDLL, "NtQuerySystemInformation");
    
    NTSTATUS STATUS = fNtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)0x23, &Sysinfo, sizeof(Sysinfo), NULL); // SystemKernelDebuggerInformation is 0x23
    if (STATUS != STATUS_SUCCESS) {
        info("Query failed with  0x%x", STATUS);
    }
    BYTE dbgEnabled = Sysinfo.DebuggerEnabled;
    BYTE dbgNotPresent = Sysinfo.DebuggerNotPresent;

    // You may check here how and when do these flag change
    // https://learn.microsoft.com/en-us/previous-versions/ff548118(v=vs.85)
    // https://learn.microsoft.com/en-us/previous-versions/ff548125(v=vs.85)

    info("dbgEnabled is 0x%x  | dbgNotPresent is 0x%x", dbgEnabled, dbgNotPresent);
    return (dbgEnabled && !dbgNotPresent);
}
```

Another way is to directly check the `KUSER_SHARED_DATA` structure which has a constant address and doesn’t seem to change regardless of the different versions of windows.

```c
BOOL _chk_KUSERSHAREDDATA() {
    unsigned char kd = *(unsigned char*) 0x7FFE02D4;
    //info("kd: 0x%x", kd);
    if ((kd & 0x01) || (kd & 0x02)) {
        info("Kernel debugger detected!");
        return TRUE;
    }
    else
        info("No kernel debugger detected");
    return FALSE;
}
```

### 7. Average Tick Counts

**Tick count** is simply the **number of milliseconds** that have passed **since the system was started.** If we calculate the difference b/w the tick count and the difference seem suspiciously high, then we know that there probably is a debugger present.

```c
BOOL _chk_tickcounts() {

    LARGE_INTEGER   Timer1 = { 0 },
        Timer2 = { 0 };

    //DWORD Timer1 = GetTickCount64();
    //DWORD Timer2 = GetTickCount64();

    if (!QueryPerformanceCounter(&Timer1)) {
        warn("Timer1 failed  @-->%d", GetLastError(0));
        return FALSE;
    }

    // run your code
    inject();

    if (!QueryPerformanceCounter(&Timer2)) {
        warn("Timer2 failed  @-->%d", GetLastError(0));
        return FALSE;
    }
    
    // Average value of counts in between is 100000
    // you would update the no. according to your need
    // if the time difference is high, we know 
    // a debugger was present bcuz of the delay
    
    if ((Timer2.QuadPart - Timer1.QuadPart) > 100000) {     
        info("SOMEONE IS DEBUGGING");
        return TRUE;
    }
    return FALSE;
}
```

### 8. Heap Flags

The Heap contains two fields `Flags` & `ForceFlags` which are affected in the presence of a debugger and by default are set to `HEAP_GROWABLE` and 0. Also when a process is created by a debugger, then Debug heaps add extra protections like guard bytes, breakpoints on buffer overruns, etc., which slow down performance but help in debugging. We can query the `HeapInfo` to check its value is set to 2 (normal) or 0 (debug heap).

{% code overflow="wrap" %}
```c
BOOL _chk_HeapFlags(HANDLE hNTDLL) {

    HANDLE hHeap = GetProcessHeap();
    ULONG HeapInfo;
    DWORD length = sizeof(HeapInfo);
    HEAP_FLAGS_INFORMATION HeapFlagsInfo;
    SIZE_T len = sizeof(HeapFlagsInfo);
    SIZE_T returnLength = 0;

    RtlQueryHeapInformation NtQueryHeapInformation = (RtlQueryHeapInformation)GetProcAddress(hNTDLL, "RtlQueryHeapInformation");

    if (hHeap == NULL) {
        warn("Failed to get the process heap handle.\n");
        return;
    }
    info("Heap Handle: %p", hHeap);

    BOOL STATUS = NtQueryHeapInformation(hHeap, HeapCompatibilityInformation, &HeapInfo, length, NULL);

    if (STATUS == STATUS_SUCCESS) {
        if (HeapInfo == 2) {
            info("No debug mode.", HeapInfo);
        }
        else {
            info("Someone's watching\n");
        }
    }
    else {
        warn("HeapQueryInformation failed with STATUS: 0x%x\n", STATUS);
    }
    
    PDWORD64 PEB = __readgsqword(0x60);
    PVOID pHeapBase = (PVOID)(*(PDWORD_PTR)((PBYTE)PEB + 0x30));
    info("pHeapBase: 0x%p", pHeapBase);
    DWORD dwHeapFlagsOffset = 0x70; // would be 0x14 for systems below Windows Vista
    DWORD dwHeapForceFlagsOffset = 0x74; // would be 0x18 for systems below Windows Vista
    DWORD pdwHeapFlags = *((PDWORD)((PBYTE)pHeapBase + dwHeapFlagsOffset));
    DWORD pdwHeapForceFlags = *((PDWORD)((PBYTE)pHeapBase + dwHeapForceFlagsOffset));
    info("Heap Flags: 0x%x", pdwHeapFlags); // 0x2 means no debug
    info("Heap ForceFlags: 0x%x", pdwHeapForceFlags); // 0x0 means no debug 
    BOOL chk = (pdwHeapFlags & ~HEAP_GROWABLE) || (pdwHeapForceFlags != 0);
    info("chk is %d", chk); // 0  means no debug
    return chk;
}
```
{% endcode %}

That’s all for now, these are just some of the few techniques possible. I’ll also add another section in future, just naming different possible anti debugging techniques. Next I’ll talk about self deletion & anti-vm techniques. As usual you can find the code uploaded on my [github](https://github.com/ZzN1NJ4/Malware-Development/blob/main/Anti-Debug/anti-debug.c), I've included a few more techniques there as well so do check that out.

## References

* [https://anti-debug.checkpoint.com/](https://anti-debug.checkpoint.com/)
* [https://github.com/ZzN1NJ4/Malware-Development/blob/main/books/README.md](https://github.com/ZzN1NJ4/Malware-Development/blob/main/books/README.md)
* [https://www.apriorit.com/dev-blog/367-anti-reverse-engineering-protection-techniques-to-use-before-releasing-software](https://www.apriorit.com/dev-blog/367-anti-reverse-engineering-protection-techniques-to-use-before-releasing-software)
* [https://xakep.ru/2018/01/17/antidebug/#toc04](https://xakep.ru/2018/01/17/antidebug/#toc04)
* [https://ling.re/hardware-breakpoints/](https://ling.re/hardware-breakpoints/)

