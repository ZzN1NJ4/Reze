---
description: Reversing executables with Ghidra
---

# Reversing with Ghidra

## Introduction

[Ghidra](https://ghidra-sre.org/) is a well known tool developed by the NSA for Reverse Engineering. It's was developed around 2019 and is a really great option to go for reversing, especially since it's open source. It differs a bit from x64dbg, as in it decompiles the executable back to C-like code\* and is mainly used for static analysis.&#x20;

> **Note\*:** Although it can also decompile executables generated from Rust / Go / any other languages apart from C, the code might seem to be a bit weird. Go to [#other-executables](reversing-with-ghidra.md#other-executables "mention") to compare the difference between Rust/Go executables.

Installation is really simple, after cloning the repo, just run the `ghidraRun.bat` (assuming you have installed the necessary dependencies) or just `choco install ghidra -y`.

## Reversing Malware

I'll reverse the same malware I did previously, but I have removed the print statements because they kinda make obvious what's going on. After running `ghidraRun.bat` just click `i` to import a file and import the executable. Then click on the executable twice and then it will ask to analyze it, click on yes. On the left, we would have a symbol tree, we can open the main function by clicking on `Functions -> m -> main`.

<figure><img src="../../.gitbook/assets/image (66).png" alt=""><figcaption></figcaption></figure>

The code here seems more readable and even though the variable name is dumb, we can hover on any variable and click `l` to rename them. We can rename them according to our understanding.

<figure><img src="../../.gitbook/assets/image (71).png" alt=""><figcaption></figcaption></figure>

There are a few `GetProcAddress` standing out and it seems that the `local_4b0` is handle to **NTDLL**. We might not know what every variable does, but no need to worry, we can figure things out eventually as we keep analyzing it. There's also `atoi` function and seems like the program is using the first argument to do something. After renaming them, it seems something like this

<figure><img src="../../.gitbook/assets/image (72).png" alt=""><figcaption></figcaption></figure>

At the last line, we see the `NtOpenProcess` function being called, so we can safely assume the variables based on the [NtOpenProcess](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-ntopenprocess) signature. We can update the variables accordingly.

```c
__kernel_entry NTSYSCALLAPI NTSTATUS NtOpenProcess(
  [out]          PHANDLE            ProcessHandle,
  [in]           ACCESS_MASK        DesiredAccess,
  [in]           POBJECT_ATTRIBUTES ObjectAttributes,
  [in, optional] PCLIENT_ID         ClientId
);
// Return value is it's status code
```

<figure><img src="../../.gitbook/assets/image (75).png" alt=""><figcaption></figcaption></figure>

We can do the same with the other functions being used and guess the variables accordingly. But we also see that for `NtAllocateVirtualMemory`, the parameter numbers do not match with the function signature, we can right click and click on override signature.&#x20;

<figure><img src="../../.gitbook/assets/image (74).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (76).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (77).png" alt=""><figcaption></figcaption></figure>

```c
__kernel_entry NTSYSCALLAPI NTSTATUS NtAllocateVirtualMemory(
  [in]      HANDLE    ProcessHandle,
  [in, out] PVOID     *BaseAddress,
  [in]      ULONG_PTR ZeroBits,
  [in, out] PSIZE_T   RegionSize,
  [in]      ULONG     AllocationType,
  [in]      ULONG     Protect
);

NtWriteVirtualMemory(
    _In_ HANDLE ProcessHandle,
    _In_opt_ PVOID BaseAddress,
    _In_reads_bytes_(NumberOfBytesToWrite) PVOID Buffer,
    _In_ SIZE_T NumberOfBytesToWrite,
    _Out_opt_ PSIZE_T NumberOfBytesWritten
    );

```

It seems that the memory was allocated with `PAGE_EXECUTE_READWRITE` which is `0x40` (check [here](https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants)). and allocated using the `MEM_COMMIT (0x2000) + MEM_RESERVE (0x1000)` which gives us the `0x3000`. Allocating memory with the `RWX` is already a big IoC (indicator of compromise) that something's fishy. For the next function, again it seems like the last parameter is missing, let's just override the signature again.

<figure><img src="../../.gitbook/assets/image (78).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (80).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (81).png" alt=""><figcaption></figcaption></figure>

Not much change, just the last parameter included which is set to 0 earlier before. Moving on, the NtCreateThreadEx function does also require fixing it's signature. (Note: `PHANDLE` is same as `HANDLE*` )

```c
NtCreateThreadEx(
    _Out_ PHANDLE ThreadHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ HANDLE ProcessHandle,
    _In_ PUSER_THREAD_START_ROUTINE StartRoutine,
    _In_opt_ PVOID Argument,
    _In_ ULONG CreateFlags, // THREAD_CREATE_FLAGS_*
    _In_ SIZE_T ZeroBits,
    _In_ SIZE_T StackSize,
    _In_ SIZE_T MaximumStackSize,
    _In_opt_ PPS_ATTRIBUTE_LIST AttributeList
    );

//    Function Signature as changed in Ghidra
//    It couldn't resolve PUSER_THREAD_START_ROUTINE, so I gave PVOID instead
//    INT_PTR func(HANDLE *, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PPS_ATTRIBUTE_LIST)
```



<figure><img src="../../.gitbook/assets/image (82).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (84).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (85).png" alt=""><figcaption></figcaption></figure>

The weird part was that `NtCreateThreadEx` takes the first parameter , a thread handle, but we see that a process handle is going. And after looking through my code, I realized that I actually was giving the process handle as first argument, probably because of the autocomplete, but it's kinda funny that it still worked and spawned the calc (probably since we didn't had their use after the thread was created).

## Other Executables

### Rust

As explained, when the executable is generated from Rust/Go, ghidra acts a bit weird, here's a look at how it tries to decompile the Rust binary. This is when I go to `main` from **functions** in **symbol tree**.

<figure><img src="../../.gitbook/assets/image (63).png" alt=""><figcaption></figcaption></figure>

After clicking the `malwares::main` , I land here. The only thing I could clearly make out is the `get_process_id_by_name` function. That's how weird it becomes.

<figure><img src="../../.gitbook/assets/image (64).png" alt=""><figcaption></figcaption></figure>

### Go

Go executables also look funny in Ghidra. This is the `main.main` function for a simple process injection program.

<figure><img src="../../.gitbook/assets/image (65).png" alt=""><figcaption></figcaption></figure>

Although there are ghidra plugins/scripts to make them more readable but I'll keep those for some other time. That's all for now.

## Conclusion

Soo, that's it ig, we were able to reverse engineer the malware and guess what was happening underneath, this was quite easy because we were dealing with C executable. Also this was a really basic process injection malware, actual malware's contain tricks & techniques to delay/confuse the analysis and make it harder to understand what's going on. I will soon post on anti-analysis, anti-debug, etc techniques. ciao.

## References

* [http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FMemory%20Management%2FVirtual%20Memory%2FNtWriteVirtualMemory.html](http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FMemory%20Management%2FVirtual%20Memory%2FNtWriteVirtualMemory.html)
* [https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntallocatevirtualmemory](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntallocatevirtualmemory)
* [https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants](https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants)
