---
hidden: true
---

# Hell's Gate

You probably have seen how to perform a direct/indirect system call. First we get a handle to NTDLL, then we get the address to our desired function (or any other func) and then we read it's code to get the SSN and the address of the `syscall` and finally use it to directly perform the syscall.&#x20;

`Hell's Gate` is just a way to dynamically retrieve the SSN and do the heavy lifting for us and we can just call the function to perform the `syscall`.&#x20;





