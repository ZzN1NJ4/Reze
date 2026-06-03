# Block DLL Policy



To block non-microsoft DLLs, we have to create a process with `PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON` flag set.&#x20;

> **Although note that this method would be useless if the EDR DLL is digitally signed by microsoft.**

to check the policies which also includes the DLL policy

```
Get-ProcessMitigation -Id 9264
```



for testing purposes, I had tried injecting our ntdll hook dll that I had created here(insert URL findstring), i would suggest use cmd.exe as a test process to create, since the injecting message is displayed which tells us we missed something in our code. but that's only because of the dll that i have injected, if it were a messagebox, then using notepad should have been fine as well.



Here's the message that we see when we try to inject a DLL using process hacker to our newly created process with the block dll policy enabled

<figure><img src="../../.gitbook/assets/image (128).png" alt=""><figcaption></figcaption></figure>



code

```
#include "helper.h"
#include <winbase.h>


BOOL CreateBlockDllPolicy(IN LPSTR path, OUT DWORD* pid, OUT HANDLE* hProcess, OUT HANDLE* hThread) {

    STARTUPINFOEXA siexA = { 0 };
    PROCESS_INFORMATION pi = { 0 };
    SIZE_T szAttrib = 0;
    PVOID pAttrib = NULL;
    PPROC_THREAD_ATTRIBUTE_LIST pThreadAttribList = NULL;
    DWORD64 dPolicy = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;

    RtlSecureZeroMemory(&siexA, sizeof(STARTUPINFOEXA));
    RtlSecureZeroMemory(&pi, sizeof(PROCESS_INFORMATION));

    siexA.StartupInfo.cb = sizeof(STARTUPINFOEXA);
    siexA.StartupInfo.dwFlags = EXTENDED_STARTUPINFO_PRESENT;

    InitializeProcThreadAttributeList(NULL, 1, 0, &szAttrib);
    pThreadAttribList = (PPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, szAttrib);
    InitializeProcThreadAttributeList(pThreadAttribList, 1, 0, &szAttrib);

    if(!UpdateProcThreadAttribute(pThreadAttribList, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, &dPolicy, sizeof(DWORD64), NULL, NULL)) {
        warn("Failed updating process thread attribute  @--0x%lx", GetLastError());
        return FALSE;
    }

    siexA.lpAttributeList = pThreadAttribList;
    getchar();
    if(!CreateProcessA(NULL, path, NULL, NULL, TRUE, EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, &siexA.StartupInfo, &pi)) {
        warn("process creation with policy failed  @--0x%lx", GetLastError());
        return FALSE;
    }

    HeapFree(GetProcessHeap(), HEAP_ZERO_MEMORY, pThreadAttribList);

    return TRUE;
}



int main(int argc, char* argv[]) {

    // CreateBlockDllPolicy();
    DWORD pid = 0;
    HANDLE hProcess = NULL;
    HANDLE hThread = NULL;
    LPSTR lpPath = "C:\\Windows\\System32\\cmd.exe";

    if(CreateBlockDllPolicy(lpPath, &pid, &hProcess, &hThread)) {
        okay("process created with block policy, pid  @-- %ld", pid);
    }
    getchar();
    return 0;
}

```

## References

* [https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute)
* [https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-setprocessmitigationpolicy](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-setprocessmitigationpolicy)
* [https://www.bordergate.co.uk/process-mitigation-policies-acg/](https://www.bordergate.co.uk/process-mitigation-policies-acg/)

