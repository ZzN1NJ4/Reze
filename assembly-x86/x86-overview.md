# x86 Architecture Overview

I wont be deep diving and explaining everything in the x86 CPU architecture (maybe some other post)  and just touch the basics, enough for us to start tinkering with assembly language. For now, just remember that there are these components in a CPU:

* Control Unit - gets instruction from main memory
* Arithmetic Unit - Executes instruction returned from main memory
* Registers - small , quickly accessible storage location
* I/O devices - mouse, keyboard, screen, etc.

Learning Assembly is important in order to better Reverse Engineer Malwares and also to develop better Malware and custom shellcode.

## Registers

Registers are like a storage medium for the CPU, they are small, fast storage location used to hold data temporarily during computation. Registers are typically used to store operands, results of operations, and addresses for memory access during program execution.

#### **EAX or RAX:**

**Accumulator Register** : often results of arithmetic operations are stored in here

This is how generally the registers are divided into their smaller counterparts, since it would be dumb to use RAX to just use only 2 bytes of data, something which can be done in AL / AH.\
\
RAX = 64 bit , EAX = 32 bit , AX = 16 bit , AH / AL = 8 bit (higher/lower)&#x20;

<figure><img src="../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

#### **EBX / RBX**

**Base Register** : Generally stores base address for referencing an offset

#### **ECX / RCX**

**Counter Register** : for counting stuffs like in a loop or similar

#### **EDX / RDX**

**Data Register** : generally used for multiplication/division

#### **ESP / RSP**

**Stack Pointer** : Always points to the top of the stack

<mark style="color:red;">**Note:**</mark> No pointer register can be addressed as smaller registers , i.e. SH/SL for ESP

#### **EBP / RBP**

**Base Pointer** : Used to access params passed by the stack

#### **ESI / RSI**

**Source Index Register** : used for string operations, used with data segment (DS) register as an offset

#### **EDI / RDI**

**Destination Index Register** : also for string operations , used with extra segment (ES) register as an offset

#### **R8 - R15**

General purpose registers which are not present 32 bit systems. Addressable in 32,16 & 8 bit modes , R8D , R8W, R8B , respectively (D - Double Word , W - Word , B - Byte)

### **Status Flag Registers**

this is a single 32 bit register called EFLAGS / RFLAGS which contains individual single bit that can be 1/0.

#### **Zero Flag**

**ZF** : indicates whether the result of last executed instruction was 0, i.e. if we do `sub RAX, RAX` , then ZF will be set to 1.

#### **Carry Flag**

**CF** : last executed instruction is too big / small for destination, eg 0xFFFFFFFF + 0x00000001 , then CF is set to 1 since value too big

#### **Sign Flag**

**SF** : sign bit as we know , tells us if the result of operation is -ve or most significant bit is set to 1 ; if yes then 1

#### **Trap Flag**

**TF** : Tells if the process is in debugging mode



<table data-header-hidden data-full-width="false"><thead><tr><th></th><th></th><th></th></tr></thead><tbody><tr><td><strong>Flag</strong></td><td><strong>Abbr.</strong></td><td><strong>Function</strong></td></tr><tr><td>Carry</td><td>CF</td><td>Set when a carry-out or borrow is required from the most significant bit in an arithmetic operation. Also used for bit-wise shifting operations.</td></tr><tr><td>Parity</td><td>PF</td><td>Set if the least significant byte of the result contains an even number of 1 bits.</td></tr><tr><td>Auxiliary</td><td>AF</td><td>Set if a carry-out or borrow is required from bit 3 to bit 4 in an arithmetic operation (BCD arithmetic).</td></tr><tr><td>Zero</td><td>ZF</td><td>Set if the result of the operation is zero.</td></tr><tr><td>Sign</td><td>SF</td><td>Set if the result of the operation is negative (i.e., the most significant bit is 1).</td></tr><tr><td>Overflow</td><td>OF</td><td>Set if there's a signed arithmetic overflow (e.g., adding two positive numbers and getting a negative result or vice versa).</td></tr><tr><td>Direction</td><td>DF</td><td>Determines the direction for string processing instructions. If DF=0, the string is processed forward; if DF=1, the string is processed backward.</td></tr><tr><td>Interrupt Enable</td><td>IF</td><td>If set (1), it enables maskable hardware interrupts. If cleared (0), interrupts are disabled.</td></tr></tbody></table>

### **Segment Registers:**

Segment Registers are 16-bit registers that convert the flat memory space into different segments for easier addressing. There are six segment registers, as explained below:

**Code Segment:** The Code Segment (CS ) register points to the Code section in the memory. \
**Data Segment:** The Data Segment (DS) register points to the program's data section in the memory. **Stack Segment:** The Stack Segment (SS) register points to the program's Stack in the memory. \
**Extra Segments (ES, FS, and GS):** These extra segment registers point to different data sections. These and the DS register divide the program's memory into four distinct data sections.

## **Operations**

### **Basic**

#### **MOV**

`mov eax, ebx` will move the value in ebx (src) , to eax (dest) `mov eax, [ebx]` || `mov eax, [edx+4]` will move the addres stored in ebx to eax. i.e. the value in ebx+4 is treated as an address pointer

#### **LEA**

`lea eax, [ebx+4]` lea is very similar to mov but instead of copying the value **in** ebx+4, it will copy the value **of** `ebx+4` , and the load that into `eax`.

#### **NOP**

nop sled , does nothing , yeah , 0x90

#### **SHIFT**

`shr/shl destination, count` shifts the bytes by the count to right / left , if the value lets say 0x101 is rotated left, i.e 0x01, then the **CF** flag is set to 1

#### **ROTATE**

`rotr / rotl destination, count` similar to shift but doesn't require any flags , so if eax is 0xAE14 , and we rotate left by 1, it becomes 0xE14A

### **Arithmetic**

#### **ADD / SUB**

`sub / add dest , source` like no need to explain but yea dest = dest -/+ source , ZF is set if result is 0 (sub) and CF is set if dest is smaller than source value

#### **INC / DEC**

`dec / inc destination` increment / decrement by 1

#### **MUL / DIV**

`div / mul value` multiply does eax \* edx and stores the value in `edx:eax` as 64 bit register cuz ofcourse, and vice versa div divides value in `edx:eax` and stores value in eax , and any remainder in edx

### **Logical**

* AND -- `and al, 0x0A`
* OR -- `or ah, 0x5A`
* NOT -- `not eax` -- just change 1100110 to 0011001
* XOR -- `xor eax,eax`

### **Conditional & Branching**

#### **TEST**

`test dest, src` performs bitwise and operation and store result in dest, sets ZF , SF

#### **CMP**

`cmp dest, src` similar to sub operation but doesn't change any registers, updates ZF to 0 if equal, changes CF if src > dest , else changes both of them

#### **JMP**

`jmp dest` jmp to the dest address

**conditional jmps**

| **jmp** | **function**                                                                                                                                          |
| ------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| jz      | Jump if the ZF is set (ZF=1).                                                                                                                         |
| jnz     | Jump if the ZF is not set (ZF=0).                                                                                                                     |
| je      | Jump if equal. Often used after a CMP instruction.                                                                                                    |
| jne     | Jump if not equal. Often used after a CMP instruction.                                                                                                |
| jg      | Jump if the destination is greater than the source operand. Performs signed comparison and is often used after a CMP instruction.                     |
| jl      | Jump if the destination is lesser than the source operand. Performs signed comparison and is often used after a CMP instruction.                      |
| jge     | Jump if greater than or equal to. Jumps if the destination operand is greater than or equal to the source operand. Similar to the above instructions. |
| jle     | Jump if lesser than or equal to. Jumps if the destination operand is lesser than or equal to the source operand. Similar to the above instructions.   |
| ja      | Jump if above. Similar to jg, but performs an unsigned comparison.                                                                                    |
| jb      | Jump if below. Similar to jl, but performs an unsigned comparison.                                                                                    |
| jae     | Jump if above or equal to. Similar to the above instructions.                                                                                         |
| jbe     | Jump if below or equal to. Similar to the above instructions.                                                                                         |

#### **PUSH**

`push dest` will push the dest on top of the stack and the esp will now point to dest `pusha / pushad` to push all words / double words

#### **POP**

`pop dest` will pop the dest from the top of stack and the stack again will realign itself `popa / popad` to pop all the words / double words

#### **CALL**

`call location` possible function call (based on the stack alignment)

Aand that's it ig, I'll walkthrough a simple assembly program in the next post

## References

* [https://www.felixcloutier.com/x86/lea](https://www.felixcloutier.com/x86/lea)

