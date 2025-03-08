---
description: Introduction to System calls
---

# System Calls

## Introduction

A system call is essentially a request sent by a user-mode program to the kernel to perform a privileged operation such as file I/O, memory management, process manipulation, etc. However, user-mode programs don’t call these functions directly. Instead, they invoke them through wrappers provided by libraries like `ntdll.dll`.&#x20;

When a syscall is triggered, the CPU switches from user mode to kernel mode, allowing the OS to execute the requested operation securely. Malwares often abuse system calls to evade detection and execute malicious code.

### SSDT — System Service Dispatch Table

The SSDT is a critical data structure in the Windows kernel that acts as a lookup table for system calls. It contains function pointers to kernel-mode routines (called **System Service Routines** or **SSRs**) that handle specific syscalls. When a user-mode application makes a syscall, the OS uses the **SSN (System Service Number)** as an index into the SSDT to locate the corresponding kernel function.

* **Location**: The SSDT resides in kernel memory and is part of the Windows Executive (the core component of the OS).
* **Purpose**: It serves as a bridge between user-mode syscalls and kernel-mode functions.

For obvious reasons, this table is protected by the OS by making it read-only and employing mechanisms like [**PatchGuard** / KPP (Kernel Patch Protection)](https://en.wikipedia.org/wiki/Kernel_Patch_Protection) to detect unauthorized modifications.&#x20;

### SSR — System Service Routine

A **System Service Routine (SSR)** is the actual kernel function responsible for executing system calls after they are dispatched from user mode. When a program in user mode requests an operation like file access, process manipulation, or memory allocation, the request is converted into a **System Service Number (SSN)** and passed to the **System Service Dispatch Table (SSDT)**. The SSDT then maps the SSN to its corresponding **SSR**, which performs the actual operation within the kernel.

### SSN — System Service Number

Each syscall is identified by a unique **System Service Number (SSN)**, which acts as an index to the **SSDT**. The **SSN** tells the kernel which specific function to execute. For example, `NtCreateFile` might have an SSN of `0x55`, while `NtOpenProcess` could be `0x26`

For Malware Analysis, knowing the SSN of a syscall is critical since it is possible to bypass higher-level APIs and invoke the syscall directly thereby avoid detection by user-mode hooks placed by security products.

**How it works**

1. A user-mode application makes a syscall (e.g., `NtOpenProcess`).
2. The syscall number (SSN) is identified and looked up in the SSDT.
3. The SSDT resolves the SSN to the correct SSR.
4. The SSR executes the requested operation in kernel mode.
5. The result is returned to user mode.

This is something which I felt is a bit unfinished, so I'll keep updating this whenever I feel the need, That's it for now. I will also soon talk about some easy - high level stuff.

