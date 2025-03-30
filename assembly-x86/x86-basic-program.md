---
description: Basic Program in x86 Assembly (Linux)
---

# x86 Basic Program

Okay, so lets start coding our first program in assembly, since this is our first program, I'll just focus on printing a string. In order to call any function, we would first have necessary parameters pushed to the stack and then finally calling the function. In our case, we would be calling the `write` system call. If you want to read more about it, you can type `man 2 write` or just lookup on google about this.

<figure><img src="../.gitbook/assets/image (23) (1) (1).png" alt=""><figcaption></figcaption></figure>

Alright, so we know that it takes 3 parameters, a file descriptor , a buffer to string , and then the size of the string. We will start with initializing our string and the length in the `.data` section and then proceed with the actual code in the `.text` section.&#x20;

### Code

```nasm
section .data
    msg db "Assembly cool! kinda", 0ah ; 0ah - line feed
    len db 0xE ; 14 in hex, we can also use 0b1110 for binary number

section .text
    global _start

_start:
    mov rax, 1      ; syscall no. for write, 4 in 32 bit 
    mov rdi, 1      ; file descriptor for stdout
    mov rsi, msg    ; we want to pass pointer to string, so [msg] wont work
    mov rdx, [len]  ; we want the value so [len] instead of the address len
    syscall         ; int 80h in 32 bit

    jmp _exit       ; jmp to _exit and end program


_exit:              ; unlike _start, we can use any label like _endme
    mov rax, 60     ; syscall no. for exit
    mov rdi, 0      ; exit status 
    syscall
```

### Explanation

So we have defined our variables in the `.data` section and in the text section we have made the `_start` global, this is done in order for the linker script to be able to access it and it serves as an entry point to the code. After this we start building our parameters, and first with the unique syscall number for the `write` syscall (the syscall numbers can be found [here](https://github.com/torvalds/linux/blob/v4.17/arch/x86/entry/syscalls/syscall_64.tbl#L11)) , `file descriptor` which defaults to 1 for `stdout`, then the pointer to the string, and finally the size of the string. I intentionally used a smaller size than the actual string to show that it will only print the string until that size.

After which we do the syscall and then `jmp` to the `_exit` label, which will then just do `exit(0)` but in assembly, there isn't much to explain here but you can lookup at man pages for `exit` function if required. It is necessary to exit the program else it might lead to unexpected behavior, although it mostly exit with some error code. For now, let's compile and run our code, you can use any online compiler (like [here](https://www.mycompiler.io/new/asm-x86_64)) or tools like `nasm` to do so. We will first create an object file from our assembly code using `nasm`, and then link it to an executable using `ld`.

```bash
nasm -f elf64 print.asm -o print.o
ld print.o -o print
./print
```

<figure><img src="../.gitbook/assets/image (24) (1) (1).png" alt=""><figcaption></figcaption></figure>

And we see our half cut string as intended. That's all for now. You can try updating the string & length and play more with the code.

