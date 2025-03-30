# PEB & TEB

## TEB

```
typedef struct _TEB {
  NT_TIB                  Tib;
  PVOID                   EnvironmentPointer;
  CLIENT_ID               Cid;
  PVOID                   ActiveRpcInfo;
  PVOID                   ThreadLocalStoragePointer;
  PPEB                    Peb;
  ULONG                   LastErrorValue;
  ULONG                   CountOfOwnedCriticalSections;
  PVOID                   CsrClientThread;
  PVOID                   Win32ThreadInfo;
  ULONG                   Win32ClientInfo[0x1F];
  PVOID                   WOW32Reserved;
  ULONG                   CurrentLocale;
  ULONG                   FpSoftwareStatusRegister;
  PVOID                   SystemReserved1[0x36];
  PVOID                   Spare1;
  ULONG                   ExceptionCode;
  ULONG                   SpareBytes1[0x28];
  PVOID                   SystemReserved2[0xA];
  ULONG                   GdiRgn;
  ULONG                   GdiPen;
  ULONG                   GdiBrush;
  CLIENT_ID               RealClientId;
  PVOID                   GdiCachedProcessHandle;
  ULONG                   GdiClientPID;
  ULONG                   GdiClientTID;
  PVOID                   GdiThreadLocaleInfo;
  PVOID                   UserReserved[5];
  PVOID                   GlDispatchTable[0x118];
  ULONG                   GlReserved1[0x1A];
  PVOID                   GlReserved2;
  PVOID                   GlSectionInfo;
  PVOID                   GlSection;
  PVOID                   GlTable;
  PVOID                   GlCurrentRC;
  PVOID                   GlContext;
  NTSTATUS                LastStatusValue;
  UNICODE_STRING          StaticUnicodeString;
  WCHAR                   StaticUnicodeBuffer[0x105];
  PVOID                   DeallocationStack;
  PVOID                   TlsSlots[0x40];
  LIST_ENTRY              TlsLinks;
  PVOID                   Vdm;
  PVOID                   ReservedForNtRpc;
  PVOID                   DbgSsReserved[0x2];
  ULONG                   HardErrorDisabled;
  PVOID                   Instrumentation[0x10];
  PVOID                   WinSockData;
  ULONG                   GdiBatchCount;
  ULONG                   Spare2;
  ULONG                   Spare3;
  ULONG                   Spare4;
  PVOID                   ReservedForOle;
  ULONG                   WaitingOnLoaderLock;
  PVOID                   StackCommit;
  PVOID                   StackCommitMax;
  PVOID                   StackReserved;

} TEB, *PTEB;
```

Thread Environment Block (TEB) is a structure in Windows that stores information about the currently running thread. Every created thread has its own `TEB` block. User can get address of `TEB` by calling the `NtCurrentTeb` function. We can also manually fetch the `TEB` using `__readgsqword`.

```c
pTEB = (PTEB)__readgsqword(0x30);
```

There are a lot of members but the most important one for us is the `PEB` which is located at an offset of `0x30` . We can also look at this in WinDbg by typing the `!teb` command to get the address of `TEB` and then `dt` command to show the structure.

<figure><img src="../.gitbook/assets/image (102).png" alt=""><figcaption></figcaption></figure>



## PEB

The **Process Environment Block (PEB)** is a structure that contains crucial information about a running process. It is created when a process starts and remains in memory throughout the process's lifetime.&#x20;

```c
typedef struct _PEB {
  BYTE                          Reserved1[2];
  BYTE                          BeingDebugged;
  BYTE                          Reserved2[1];
  PVOID                         Reserved3[2];
  PPEB_LDR_DATA                 Ldr;
  PRTL_USER_PROCESS_PARAMETERS  ProcessParameters;
  PVOID                         Reserved4[3];
  PVOID                         AtlThunkSListPtr;
  PVOID                         Reserved5;
  ULONG                         Reserved6;
  PVOID                         Reserved7;
  ULONG                         Reserved8;
  ULONG                         AtlThunkSListPtr32;
  PVOID                         Reserved9[45];
  BYTE                          Reserved10[96];
  PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
  BYTE                          Reserved11[128];
  PVOID                         Reserved12[1];
  ULONG                         SessionId;
} PEB, *PPEB;
```

We can guess a few members like `BeingDebugged` & `ProcessParameters`. We can query PEB using the same `__readgsqword` function.

<pre class="language-c"><code class="lang-c"><strong>PPEB pPEB = (PEB)__readgsqword(0x60)
</strong><strong>// In case you wonder why is TEB at gs:[0x30] but PEB gs:[0x60]
</strong><strong>// even though PEB is at an offset of 0x60 from TEB
</strong><strong>// This is because the gs register contains a list of important structures/members 
</strong><strong>// like TEB , PID , PEB , etc.
</strong><strong>// Refer https://en.wikipedia.org/wiki/Win32_Thread_Information_Block
</strong></code></pre>

<figure><img src="../.gitbook/assets/image (105).png" alt=""><figcaption><p>get PID from gs:[0x40]</p></figcaption></figure>

If we look at `PEB` in WinDbg, we can see that the `BeingDebugged` member is set to `0x1` (true) which is correct since we are debugging the process right now.

<figure><img src="../.gitbook/assets/image (103).png" alt=""><figcaption></figcaption></figure>

It also contains the Ldr member which contains information regarding the image (DLL) loaded in the process. We can also see that in WinDbg

<figure><img src="../.gitbook/assets/image (104).png" alt=""><figcaption></figcaption></figure>

We can see all the different DLL being loaded into the notepad process.

All in all, TEB & PEB are really important structures and understanding them well is important for both developing & analyzing malwares.&#x20;

