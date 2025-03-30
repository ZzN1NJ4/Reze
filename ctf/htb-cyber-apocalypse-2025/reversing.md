# Reversing

I couldn't do much in here. I still have a lot to learn in reversing, but I did manage to solve 2 challenges. Here's the writeup for them

## Encrypted Scrolls - Very Easy

<figure><img src="../../.gitbook/assets/image (106).png" alt=""><figcaption></figcaption></figure>

Downloading the file, we see a binary, running it gives this

<figure><img src="../../.gitbook/assets/image (107).png" alt=""><figcaption></figcaption></figure>

Seems like I can't use strace / ltrace. I do see the ptrace call, which is probably being used to check whether the process is being debugged / inspected.&#x20;

<figure><img src="../../.gitbook/assets/image (109).png" alt=""><figcaption><p>ltrace</p></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (108).png" alt=""><figcaption><p>strace</p></figcaption></figure>

I decided to open it in Ghidra to get a closer look at it. There is an interesting function called decrypt message. Looking at it, there seems to be a few variables defined, then a for loop which subtracts 1 from every single character in the hex, and then finally comparing it with the user input.&#x20;

<figure><img src="../../.gitbook/assets/image (34).png" alt=""><figcaption><p>main function</p></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (35).png" alt=""><figcaption><p>decrypt_message</p></figcaption></figure>

Writing a simple python code to do the same, and print the value, I see that its the starting of the flag. We can do the same with other hex values and get the flag.

<figure><img src="../../.gitbook/assets/image (36).png" alt=""><figcaption></figcaption></figure>

I wrote a short python code to do this for all the hex , and got the flag

```python
value1 = [0x71,0x6e,0x32,0x74,0x7c,0x43,0x55,0x49]
value2 = [0x67, 0x60, 0x34, 0x6d]
value3 = [0x60, 0x68, 0x35, 0x6d]
value4 = [0x75, 0x32, 0x73, 0x35]
value5 = [0x7e, 0x64, 0x32, 0x75, 0x34, 0x6e, 0x69]

def decrypt(value):
    dec = []
    for i in value:
        dec.append(i-1)
    
    string = ""

    for i in dec:
        string = string + chr(i)

    return string

print(decrypt(value1)[::-1],decrypt(value2)[::-1],decrypt(value3)[::-1], decrypt(value4)[::-1], decrypt(value5)[::-1])
```

<figure><img src="../../.gitbook/assets/image (37).png" alt=""><figcaption></figcaption></figure>

Flag: `HTB{s1mpl3_fl4g_4r1thm3t1c}`



## Sealed Rune - Very Easy

Downloading and running the binary, I see this

<figure><img src="../../.gitbook/assets/image (38).png" alt=""><figcaption></figcaption></figure>

there were 2 ways that I solved it, ill show the easy one first. When running strings on it. We see 2 interesting base64 encoded strings and also the function base64\_decode.&#x20;

<figure><img src="../../.gitbook/assets/image (39).png" alt=""><figcaption></figcaption></figure>

decrypting those, we get the password to the challenge & also the flag , but in reverse. We can easily reverse them again&#x20;

<figure><img src="../../.gitbook/assets/image (40).png" alt=""><figcaption></figcaption></figure>

The other way I did this was to use r2 and directly jmp on the address of the function decode\_flag which prints the flag directly. First I set the breakpoint at the anti\_debug function.

<figure><img src="../../.gitbook/assets/image (41).png" alt=""><figcaption></figcaption></figure>

Next, I just need to find the function being called to decrypt the flag. The check\_input function has another function called decode\_flag. I'll directly set the RIP to that address&#x20;

<figure><img src="../../.gitbook/assets/image (42).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (43).png" alt=""><figcaption></figcaption></figure>

