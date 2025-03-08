---
description: >-
  Injecting shellcode into legitimate process by abusing the Windows APC
  technique
---

# APC Injection

## Introduction

APC (Asynchronous Procedure Call) is a function that executes asynchronously (as the name suggests) in the context of a particular thread. These are generally used for I/O stuff, etc. \
Each thread has its own APC queue. An application queues an APC to a thread by calling the [**QueueUserAPC**](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-queueuserapc) function. The calling thread specifies the address of an APC function in the call to **QueueUserAPC**.  When an APC is queued, a request is made for the thread to call the APC function.

It's like OS saying to the thread "Hey, look at this whenever you have the time." Now the importante thing to note is that it is only possible to queue an APC for a thread if and only if that particular thread is in alertable state. According to MSDN

> A thread enters an alertable state when it calls the [**SleepEx**](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-sleepex), [**SignalObjectAndWait**](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-signalobjectandwait), [**MsgWaitForMultipleObjectsEx**](https://learn.microsoft.com/en-us/windows/desktop/api/Winuser/nf-winuser-msgwaitformultipleobjectsex), [**WaitForMultipleObjectsEx**](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-msgwaitformultipleobjectsex), or [**WaitForSingleObjectEx**](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitforsingleobjectex).

&#x20;If we queue the APC for any non-alertable thread, we would have to wait until it goes into an alertable state and then it will run our code.&#x20;

Now let's take a look at the function [**QueueUserAPC**](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-queueuserapc)**.**

```c
DWORD QueueUserAPC(
  [in] PAPCFUNC  pfnAPC,
  [in] HANDLE    hThread,
  [in] ULONG_PTR dwData
);
```

* <mark style="color:purple;">**dwData**</mark> - A single value that is passed as parameter to the function to be called.
* <mark style="color:purple;">**hThread**</mark> - Handle to the thread in alertable state. It must have the **THREAD\_SET\_CONTEXT** access right.
* <mark style="color:purple;">**pfnAPC**</mark> - A pointer to the APC Function to be called.

If the function succeeds, the return value will be non-zero, else it will be 0 (failure).

### Simple explaination

Imagine you work in a company and you are currently doing an important task which will take you an hour to do. But then your boss comes in and hands you some files to verify later. Now you have become a thread and your boss has queued an APC call, you won't stop your work immediately to do the verification but you will have to do it after you finish your task. This is the case with Regular APC calls.

Special User-Mode APC calls are a bit special. Now imagine the same scenario where you are doing the task but this time, the CEO of your company has approached you with a "really important" task to do it immediately. You would then have to pause your work and finish the CEO's work first and only then resume what you were doing. The problem here is that since you have only 1 notebook and you do both of the work in it, there is a possibility of "[race condition](https://en.wikipedia.org/wiki/Race_condition)" and messing things up. That's why special care needs to be taken when running the special APC.



## Execution Flow

1. Create a thread that runs any function which allows it to switch to alertable state.
2. Inject the shellcode into Process Memory.
3. Call QueueUserAPC with the shellcode base address as the function.

## APC Injection

Alright, so first we will create another function which would contain any of the function that helps the thread to switch to alertable state. Those are  [`SleepEx`](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-sleepex)`,`[`SignalObjectAndWait`](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-signalobjectandwait)`,`[`WaitForSingleObjectEx`](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitforsingleobjectex)`,`[`WaitForMultipleObjectsEx`](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitformultipleobjectsex)`,` [`MsgWaitForMultipleObjectsEx`](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-msgwaitformultipleobjectsex). I have used `SleepEx` for simplicity. Note that the 2nd Parameter should be set to `TRUE` for the Thread to go in alertable state.

```c
VOID Aleeert() {
	info("Thread ID : %d", GetCurrentThreadId());
	SleepEx(INFINITE, TRUE);
}
```

Now we just have to allocate memory for our shellcode and give it to the `QueueUserAPC` to run it.

```c
int main() {
	HANDLE hThread = NULL;
	info("Main Thread : %d", GetCurrentThreadId());
	hThread = CreateThread(NULL, 0, Aleeert, 0, 0, NULL);
	
	PVOID pFunc = VirtualAlloc(NULL, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	memcpy(pFunc, shellcode, sizeof(shellcode));
	
	//Sleep(1);

	// Not necessary to typecast pFunc but me do me
	QueueUserAPC((PAPCFUNC)pFunc, hThread, NULL);
	// if we don't wait for the thread to finish execution
	// program exits before the thread is able to run our shellcode
	WaitForSingleObject(hThread, INFINITE);
	CloseHandle(hThread);

	return 0;
}
```

Here I did notice that if we do not have the Sleep function, I don't see the print statement in the function although the thread does execute our shellcode&#x20;

<figure><img src="../../.gitbook/assets/image (26) (1).png" alt=""><figcaption></figcaption></figure>

But when I do have the Sleep function, I see the print statement in the `Aleeert` function. After a failed chatgpt interaction and a little document searching, I found this on MSDN,

> If an application queues an APC before the thread begins running, the thread begins by calling the APC function. After the thread calls an APC function, it calls the APC functions for all APCs in its APC queue.

So it means that our code was queued even before the thread got the time to run the function, this I can prove by removing the `SleepEx` function which means that our **thread** should not be in the **alertable** state yet it runs our shellcode because of us queueing it before it can even run.

<figure><img src="../../.gitbook/assets/image (29).png" alt=""><figcaption></figcaption></figure>

One thing to note is that we still are allocating memory with `PAGE_EXECUTE_READWRITE` which is a **very big red flag** that we are doing something suspicious. We can eliminate that by allocating our shellcode to the `.text` section as I have shown here\[link] previously.

```c
#pragma section(".text")

__declspec(allocate(".text")) char shellcode[] =
"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50"
....
```

And we see that we are able to execute our shellcode neatly without allocating any RWX memory.

<figure><img src="../../.gitbook/assets/image (31).png" alt=""><figcaption></figcaption></figure>

Alright since we technically haven't played with alertable thread yet, I'll create a thread that goes into alertable state and only then do we queue the APC for it to run.

<figure><img src="../../.gitbook/assets/image (38).png" alt=""><figcaption></figcaption></figure>

We know that the thread was in alertable state since it did ran our shellcode, you can try removing the `SleepEx` function and run the program again, the shellcode won't run since the thread wont be in alertable state.

## VirusTotal

Out of curiousity, I wanted to check this against VirusTotal and I was kinda surprised at the rate of detection ( 423094eabcc7ffa09ba35d3c6df2d3a4cecc9505fcd9bb4e629cb675c2e5e122 ). I have used the binary where I allocate shellcode in `.text` section.

<figure><img src="../../.gitbook/assets/image (32).png" alt=""><figcaption></figcaption></figure>

This is not bad because almost all of them AV flagged this because of the msf payload, so if we were to use any other custom payload, the rate will go considerably low.

Alright that's it for now, This became lengthier than what I was expecting so I have broken it into 2 parts, ciao. I'll be back with more interesting techniques to talk about, probably system calls, but there are soo many more things to explore. Hopefully, I was good enough to help you understand how this works.

## References

* [https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-queueuserapc](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-queueuserapc)
* [https://repnz.github.io/posts/apc/user-apc/#ntqueueapcthread-system-call-layer](https://repnz.github.io/posts/apc/user-apc/#ntqueueapcthread-system-call-layer)
* [https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/types-of-apcs](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/types-of-apcs)
* [https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-queueuserapc2](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-queueuserapc2)
* [https://www.ired.team/offensive-security/code-injection-process-injection/apc-queue-code-injection](https://www.ired.team/offensive-security/code-injection-process-injection/apc-queue-code-injection)









