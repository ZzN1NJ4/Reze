# PE Structure

## Introduction

According to [wikipidea](https://en.wikipedia.org/wiki/Portable_Executable), The **Portable Executable** (**PE**) format is a [file format](https://en.wikipedia.org/wiki/File_format) for [executables](https://en.wikipedia.org/wiki/Executable), [object code](https://en.wikipedia.org/wiki/Object_file), [DLLs](https://en.wikipedia.org/wiki/Dynamic-link_library) and others used in 32-bit and 64-bit versions of [Windows](https://en.wikipedia.org/wiki/Microsoft_Windows) [operating systems](https://en.wikipedia.org/wiki/Operating_system), and in [UEFI](https://en.wikipedia.org/wiki/UEFI) environments. As someone who wants to write / reverse engineer a Malware, it is important to delve deep into the structure of a PE file, so let's start without using any more time.

## DOS Header

Any PE file starts with MZ or `4d 5a` (reversed due to little-endian format) which is also known as the magic byte of the file. The magic bytes of a file define which kind of file would it be, for eg. a JPG starts with `FF D8 FF`.\
The first 64 bytes of the PE file is `IMAGE_DOS_HEADER` structure , the main reason for its existence is backward compatibility. We can find the structure definition in `winnt.h` (which can be found here https://codemachine.com/downloads/win80/winnt.h)

```c
typedef struct _IMAGE_DOS_HEADER {      // DOS .EXE header
    WORD   e_magic;                     // Magic number
    WORD   e_cblp;                      // Bytes on last page of file
    WORD   e_cp;                        // Pages in file
    WORD   e_crlc;                      // Relocations
    WORD   e_cparhdr;                   // Size of header in paragraphs
    WORD   e_minalloc;                  // Minimum extra paragraphs needed
    WORD   e_maxalloc;                  // Maximum extra paragraphs needed
    WORD   e_ss;                        // Initial (relative) SS value
    WORD   e_sp;                        // Initial SP value
    WORD   e_csum;                      // Checksum
    WORD   e_ip;                        // Initial IP value
    WORD   e_cs;                        // Initial (relative) CS value
    WORD   e_lfarlc;                    // File address of relocation table
    WORD   e_ovno;                      // Overlay number
    WORD   e_res[4];                    // Reserved words
    WORD   e_oemid;                     // OEM identifier (for e_oeminfo)
    WORD   e_oeminfo;                   // OEM information; e_oemid specific
    WORD   e_res2[10];                  // Reserved words
    LONG   e_lfanew;                    // File address of new exe header
  } IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;
```

There are a lot of fields but we are interested in only few of them like `e_lfanew` which points to `IMAGE_NT_HEADERS` which is another structure. Since we know the type of all the members, we can calculate the offset of the member `e_lfanew` which would be (word = 2 bytes, 16 members , an array of 4 word, and an array of 10 words).&#x20;

$$
(2*16) + (2*4) + (2*10) = 60
$$

which is `0x3C` in hex, so the address of `IMAGE_NT_HEADERS` is at offset 0x3C from the start of the PE file.

### DOS Stub

After the `IMAGE_DOS_HEADER` we have the DOS stub which again isn't importante, it runs the message "This program cannot be run in DOS mode" and then exits. Ill ignore this but if you want to know more , you can check [0xrick's blog](https://0xrick.github.io/win-internals/pe3/) on it.

### Rich Headers

We have Rich Headers in between the DOS Stub and the NT Headers , and the special thing about it is that it is an undocumented structure and also that it is only present in the PE developed using the Microsoft Visual Studio. It contains metadata about the tools used and their specific versions.  You can check [this page](https://www.virusbulletin.com/virusbulletin/2020/01/vb2019-paper-rich-headers-leveraging-mysterious-artifact-pe-format/) , [and this](https://offwhitesecurity.dev/malware-development/portable-executable-pe/rich-header/) out for more on Rich Headers.

## NT Headers

Here is the definition of NT Headers from `winnt.h` file, It has 2 variants, one for 32-bit and other for 64-bit systems, the first member is the same `DWORD Signature` and has a constant value of `50 45 00 00` which translates to `PE` and the 2 null bytes. Apart from that , there is a File Header structure and an Optional Header structure.

```c
typedef struct _IMAGE_NT_HEADERS64 {
    DWORD Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;

typedef struct _IMAGE_NT_HEADERS {
    DWORD Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER32 OptionalHeader;
} IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;
```

### File Header

The File Header structure looks like this (aka Coff Header)

```c
typedef struct _IMAGE_FILE_HEADER {
    WORD    Machine;
    WORD    NumberOfSections;
    DWORD   TimeDateStamp;
    DWORD   PointerToSymbolTable;
    DWORD   NumberOfSymbols;
    WORD    SizeOfOptionalHeader;
    WORD    Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;
```

it talks about few things like the

* **`Machine`**: specifies whether the PE is for 32 / 64 bit architecture.
* **`NumberOfSections`**: The no. of sections the PE has.
* **`TimeDateStamp`**: date & time of binary compilation.
* **`PointerToSymbolTable`**: Offset to the COFF Symbol table
* **`NumberOfSymboles`**: No. of symbols in that table
* **`SizeOfOptionalHeader`**: clearly says what it is
* **`Characteristics`**: which talks about the characteristics of the PE file.

### Optional Header

Then we have the Optional Header which is considered to be one of the most important information centric structure , Here's the definition (from [MSDN page](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_optional_header32))

```c
typedef struct _IMAGE_OPTIONAL_HEADER {
  WORD                 Magic;
  BYTE                 MajorLinkerVersion;
  BYTE                 MinorLinkerVersion;
  DWORD                SizeOfCode;
  DWORD                SizeOfInitializedData;
  DWORD                SizeOfUninitializedData;
  DWORD                AddressOfEntryPoint;
  DWORD                BaseOfCode;
  DWORD                BaseOfData;
  DWORD                ImageBase;
  DWORD                SectionAlignment;
  DWORD                FileAlignment;
  WORD                 MajorOperatingSystemVersion;
  WORD                 MinorOperatingSystemVersion;
  WORD                 MajorImageVersion;
  WORD                 MinorImageVersion;
  WORD                 MajorSubsystemVersion;
  WORD                 MinorSubsystemVersion;
  DWORD                Win32VersionValue;
  DWORD                SizeOfImage;
  DWORD                SizeOfHeaders;
  DWORD                CheckSum;
  WORD                 Subsystem;
  WORD                 DllCharacteristics;
  DWORD                SizeOfStackReserve;
  DWORD                SizeOfStackCommit;
  DWORD                SizeOfHeapReserve;
  DWORD                SizeOfHeapCommit;
  DWORD                LoaderFlags;
  DWORD                NumberOfRvaAndSizes;
  IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;
```

* **`Magic`**: which specifies whether the system is 32 bit (0x010B) or 64 bit (0x020B)
* **`AddressOfEntryPoint`**: which lets us know from where will the windows begin the execution of the PE. This is a Relative Virtual Address (RVA) which means that it is at an offset of `ImageBase + RVA`.
* **`ImageBase`**: The preferred base address of the PE when loaded into memory which is generally `0x00400000` for exe files but of course not every file can run with same base address so it may be different for some.
* **`BaseOfCode`**& **`BaseOfData`**: RVA for Code segment & Data Segment.
* **`Subsystem`**: Lets us know which subsystem is required to run the image. (See full list at [MSDN document](https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_optional_header32) )
* **`DataDirectory`**: The data directory indicates where to find other important components of executable information in the file. It is really nothing more than an array of **`IMAGE_DATA_DIRECTORY`** structure. There are 16 possible `DataDirectory`.

### Data Directory

The last member is `DataDirectory` which is of type `IMAGE_DATA_DIRECTORY` and the `IMAGE_NUMBEROF_DIRECTORY_ENTRIES` is a constant value of 16, so basically there would be 16 `DataDirectory` , looking at the structure `IMAGE_DATA_DIRECTORY`

```c
typedef struct _IMAGE_DATA_DIRECTORY {
    DWORD   VirtualAddress;
    DWORD   Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;
```

These are the directories with the last one (15th) being reserved, we can see this in winnt.h file

```c
// Directory Entries

#define IMAGE_DIRECTORY_ENTRY_EXPORT          0   // Export Directory
#define IMAGE_DIRECTORY_ENTRY_IMPORT          1   // Import Directory
#define IMAGE_DIRECTORY_ENTRY_RESOURCE        2   // Resource Directory
#define IMAGE_DIRECTORY_ENTRY_EXCEPTION       3   // Exception Directory
#define IMAGE_DIRECTORY_ENTRY_SECURITY        4   // Security Directory
#define IMAGE_DIRECTORY_ENTRY_BASERELOC       5   // Base Relocation Table
#define IMAGE_DIRECTORY_ENTRY_DEBUG           6   // Debug Directory
//      IMAGE_DIRECTORY_ENTRY_COPYRIGHT       7   // (X86 usage)
#define IMAGE_DIRECTORY_ENTRY_ARCHITECTURE    7   // Architecture Specific Data
#define IMAGE_DIRECTORY_ENTRY_GLOBALPTR       8   // RVA of GP
#define IMAGE_DIRECTORY_ENTRY_TLS             9   // TLS Directory
#define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG    10   // Load Configuration Directory
#define IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT   11   // Bound Import Directory in headers
#define IMAGE_DIRECTORY_ENTRY_IAT            12   // Import Address Table
#define IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT   13   // Delay Load Import Descriptors
#define IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR 14   // COM Runtime descriptor
```

the Export Directory and the Import Directory , also known as Export Address Table (EAT) and Import Address Table (IAT) are the 2 important directories from both developing and analyzing malware point of view. IAT contains a ton of information and important structures like the `Process Environment Block (PEB)` and `Thread Environment Block (TEB)` and tells us the about the winapi functions are being used. So something like a `VirtualAllocEx` and `CreateProcessThread` along with `WriteProcessMemory` would point us towards high possibility of process injection.

## Section Header

Then comes the Section Header which contains information on the different sections and their sizes in the PE file. the structure looks like this (from `winnt.h`)

```c
typedef struct _IMAGE_SECTION_HEADER {
    BYTE    Name[IMAGE_SIZEOF_SHORT_NAME];
    union {
            DWORD   PhysicalAddress;
            DWORD   VirtualSize;
    } Misc;
    DWORD   VirtualAddress;
    DWORD   SizeOfRawData;
    DWORD   PointerToRawData;
    DWORD   PointerToRelocations;
    DWORD   PointerToLinenumbers;
    WORD    NumberOfRelocations;
    WORD    NumberOfLinenumbers;
    DWORD   Characteristics;
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;
```

There are different sections having different purpose mentioned below:

1. **`.text`** stores the actual code of the program
2. **`.data`** holds the initialized and defined variables
3. **`.bss`** holds the uninitialized data (declared variables with no assigned values)
4. **`.rdata`** contains the read-only data
5. **`.edata`**: contains exportable objects and related table information
6. **`.idata`** imported objects and related table information
7. **.`reloc`** image relocation information
8. **`.rsrc`** links external resources used by the program such as images, icons, embedded binaries, and manifest file, which has all information about program versions, authors, company, and copyright.

## Import Directory (IAT & ILT)

Now whenever we import the functions from windows api , all of these information gets stored in the `.idata` section. The `.idata` section consists of `IMAGE_IMPORT_DIRECTORY` which consists of series of `_IMAGE_IMPORT_DESCRIPTOR` structures

```c
typedef struct _IMAGE_IMPORT_DESCRIPTOR
{
 
    union {
        DWORD Characteristics; // 0 for terminating null import descriptor
        DWORD OriginalFirstThunk; // RVA to original unbound IAT (PIMAGE_THUNK_DATA) / ILT
    } DUMMYUNIONNAME;
 
    DWORD TimeDateStamp; // 0 if not bound,
                         // -1 if bound, and real date	ime stamp
                         // in IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT (new BIND)
                         // O.W. date/time stamp of DLL bound to (Old BIND)
    
    DWORD ForwarderChain; // -1 if no forwarders
    DWORD Name;
    DWORD FirstThunk; // RVA to IAT (if bound this IAT has actual addresses)
 
} IMAGE_IMPORT_DESCRIPTOR;
```

The **`OriginalFirstThunk`** member points to the ILT or the Import Lookup Table which is very similar to IAT but the only thing is that it remains static and contains RVA and ordinal or hint-name table for the functions imported, and the IAT gets overwritten with the address of the imported functions when the binary is loaded. the reason behind this behavior is explained well [here](https://community.broadcom.com/symantecenterprise/viewdocument/dynamic-linking-in-linux-and-window?CommunityKey=1ecf5f55-9545-44d6-b0f4-4e4a7f5f5e68\&tab=librarydocuments), the hint-name table structure is as follows

```c
typedef struct _IMAGE_IMPORT_BY_NAME {
    WORD    Hint;
    CHAR   Name[1];
} IMAGE_IMPORT_BY_NAME, *PIMAGE_IMPORT_BY_NAME;
```

where the Hint is the number that is used to lookup the function, its first used as index to Export Name Table pointer array (of the DLL) , and if that is incorrect then a binary search is performed.

## Conclusion

In conclusion, The `IMAGE_IMPORT_DESCRIPTOR` structure defines function imports in PE files, with `OriginalFirstThunk` pointing to the **Import Lookup Table (ILT)**, which contains function names or ordinals, and `FirstThunk` pointing to the **Import Address Table (IAT)**, where function addresses are stored once resolved at runtime. The ILT remains static while the IAT is updated when the program loads, allowing dynamic linking of external libraries without tying the application to specific function addresses.

I will soon write another post dissecting a PE and showing most of the things I have said here.

## References

* [https://offwhitesecurity.dev/malware-development/portable-executable-pe/rich-header/](https://offwhitesecurity.dev/malware-development/portable-executable-pe/rich-header/)
* [https://learn.microsoft.com/en-us/windows/win32/debug/pe-format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
* [https://0xrick.github.io/win-internals/pe6/](https://0xrick.github.io/win-internals/pe6/)
* [https://community.broadcom.com/symantecenterprise/viewdocument/dynamic-linking-in-linux-and-window?CommunityKey=1ecf5f55-9545-44d6-b0f4-4e4a7f5f5e68\&tab=librarydocuments](https://community.broadcom.com/symantecenterprise/viewdocument/dynamic-linking-in-linux-and-window?CommunityKey=1ecf5f55-9545-44d6-b0f4-4e4a7f5f5e68\&tab=librarydocuments)
* [http://sandsprite.com/CodeStuff/Understanding\_imports.html](http://sandsprite.com/CodeStuff/Understanding_imports.html)
* [https://learn.microsoft.com/en-us/previous-versions/ms809762(v=msdn.10)?redirectedfrom=MSDN](https://learn.microsoft.com/en-us/previous-versions/ms809762\(v=msdn.10\)?redirectedfrom=MSDN)

