---
description: >-
  5 - Baby Rev, Loginator.out , Appreciation of Art , Praise our RNG Gods,
  Reverse Mishaps
---

# Reversing

## Baby Rev

<figure><img src="../../.gitbook/assets/image (8) (1) (1).png" alt=""><figcaption></figcaption></figure>

There is a file chall.py provided to us, looking into it, we see this&#x20;

```python
# Python obfuscation by freecodingtools.org
                    
_ = lambda __ : __import__('zlib').decompress(__import__('base64').b64decode(__[::-1]));exec((_)(b'==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'))
```

So there is a base64 string which is in reverse and after it has been "unreversed", it is base64 decoded and decompressed using zlib. There is also the site given from where it was obfuscated. I wrote a small code to do this once and got the same output (a reverse b64 encoded string). So I automated it with python until I get something else.

```python
import re
import base64
import zlib

count = 0
enc = "==L0NGstringREVERSED"

while True:
    try:
        print("COUNT : ", count)
        count += 1

        rev_enc = enc[::-1]
        decoded = base64.b64decode(rev_enc)
        decompressed = zlib.decompress(decoded)
        enc = decompressed.decode(errors="ignore")
        print(decompressed)
        test=decompressed; enc=test[10:]

    except Exception as e:
        print(f"Error occurred: {e}")
        break
```

<figure><img src="../../.gitbook/assets/image (7) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

## Loginator.out

For this one, we had given a file loginator.out and a series of hex strings. On running the binary, we see that it encodes the string in hex and prints it back.

<figure><img src="../../.gitbook/assets/image (8) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

After running the binary, we can see that it obfuscates the string back to hex and prints it, so that weird hex provided to us might be the target hex for the flag ig

<figure><img src="../../.gitbook/assets/image (11) (1) (1).png" alt=""><figcaption></figcaption></figure>

> 02 92 a8 06 77 a8 32 3f 15 68 c9 77 de 86 99 7d 08 60 8e 64 77 be ba 74 26 96 e7 4e

with some guess work, I could make out a few initial characters and quickly wrote a python script to brute force all the others. Although I could "reverse" the binary and find out how it worked, this was way easier.

<figure><img src="../../.gitbook/assets/image (9) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

I automate the guess work in python until I find the matching hex and continue until I get to the end of the flag

```python
import subprocess
import string

target = bytes.fromhex("02 92 a8 06 77 a8 32 3f 15 68 c9 77 de 86 99 7d 08 60 8e 64 77 be ba 74 26 96 e7 4e".replace("" , ""))

flag = "BITSCTF{"
possible="0123456789ABCDEFabcdef"

while "}" not in flag:
    for char in string.printable:
        attempt = flag + char
        result = subprocess.run(["./loginator.out", attempt], capture_output=True, text=True)
        output = result.stdout.strip()

        b_output = bytes.fromhex(output.replace(" ", "")) if all(c in "0123456789abcdefABCDEF " for c in output) else None
        if b_output and b_output.startswith(target[:len(b_output)]):  
            flag += char
            print(f"Flag: {flag}")
            break
```



<figure><img src="../../.gitbook/assets/image (10) (1) (1).png" alt=""><figcaption></figcaption></figure>

## Appreciation of Art

<figure><img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

We are given a binary `a.art` and this is what we see on running it

<figure><img src="../../.gitbook/assets/image (12) (1) (1).png" alt=""><figcaption></figcaption></figure>

Once again, This was something that I didn't exactly "reversed" and took a shortcut lol, but first comes some initial analysis I did.

<figure><img src="../../.gitbook/assets/image (13) (1) (1).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (14) (1) (1).png" alt=""><figcaption></figcaption></figure>

So It's a stripped binary, x64 and my guess for the reason behind those single char write calls is that they really didn't wanted us to look into any strings inside the binary. Running strings only gives us this

<figure><img src="../../.gitbook/assets/image (15) (1) (1).png" alt=""><figcaption></figcaption></figure>

I did try r2 to reverse it but then quickly decided to take a simpler approach. I run the program again and then crash it using `gcore` to get the core dump and grep for strings in it. First we need to enable the core dump.

```bash
ulimit -c  # if 0 , then it's disabled
ulimit -c unlimited  # Now we can have core dump of any size
./a.art
ps aux | grep a.art
gcore -o dump <pid>
```

<figure><img src="../../.gitbook/assets/image (16) (1) (1).png" alt=""><figcaption></figcaption></figure>

Although I still couldn't see what was the name of the character , I did get the flag.

<figure><img src="../../.gitbook/assets/image (17) (1) (1).png" alt=""><figcaption></figcaption></figure>

Well, This was something I genuinely want to know the intended solution for.&#x20;

## Praise our RNG Gods

<figure><img src="../../.gitbook/assets/image (2) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

We are given a `chall.txt` file and a netcat server to connect to. I had never seen a python bytecode disassembled so I skipped it but then later visited this challenge again and managed to reverse it. Although I was late and so couldn't complete the challenge.

<figure><img src="../../.gitbook/assets/image (4) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

````0
2 LOAD_CONST 1 (None)
4 IMPORT_NAME 0 (random)
6 STORE_NAME 0 (random)

8 LOAD_CONST 0 (0)
10 LOAD_CONST 1 (None)
12 IMPORT_NAME 1 (os)
14 STORE_NAME 1 (os)

16 LOAD_NAME 2 (int)
18 LOAD_ATTR 7 (NULL|self + from_bytes)
20 PUSH_NULL
22 LOAD_NAME 1 (os)
24 LOAD_ATTR 8 (urandom)
26 LOAD_CONST 2 (8)
28 CALL 1
30 LOAD_CONST 3 ("big")
32 CALL 2
34 STORE_NAME 5 (seed)

36 PUSH_NULL
38 LOAD_NAME 0 (random)
40 LOAD_ATTR 10 (seed)
42 LOAD_NAME 5 (seed)
44 CALL 1
46 POP_TOP

48 LOAD_CONST 4 ("REDACTED")
50 STORE_NAME 6 (flag)

52 LOAD_CONST 5 (code object generate_password)
54 MAKE_FUNCTION 0 (No arguments)
56 STORE_NAME 7 (generate_password)

58 PUSH_NULL
60 LOAD_NAME 8 (print)
62 LOAD_CONST 6 ("Vault is locked! Enter the password to unlock.")
64 CALL 1
66 POP_TOP

68 LOAD_CONST 7 (1)
70 STORE_NAME 9 (i)

72 NOP

74 PUSH_NULL
76 LOAD_NAME 7 (generate_password)
78 LOAD_NAME 9 (i)
80 CALL 1
82 STORE_NAME 10 (password)

84 PUSH_NULL
86 LOAD_NAME 11 (input)
88 LOAD_CONST 8 ("> ")
90 CALL 1
92 STORE_NAME 12 (attempt)

94 LOAD_NAME 12 (attempt)
96 LOAD_ATTR 27 (NULL|self + isdigit)
98 CALL 0
100 POP_JUMP_IF_TRUE 9 (to 114)

102 PUSH_NULL
104 LOAD_NAME 8 (print)
106 LOAD_CONST 9 ("Invalid input! Enter a number.")
108 CALL 1
110 POP_TOP

112 JUMP_BACKWARD 42 (to 72)

114 PUSH_NULL
116 LOAD_NAME 14 (abs)
118 LOAD_NAME 10 (password)
120 PUSH_NULL
122 LOAD_NAME 2 (int)
124 LOAD_NAME 12 (attempt)
126 CALL 1
128 BINARY_OP 10 (-)
130 CALL 1
132 STORE_NAME 15 (difference)

134 LOAD_NAME 15 (difference)
136 LOAD_CONST 0 (0)
138 COMPARE_OP 40 (==)
140 POP_JUMP_IF_FALSE 10 (to 156)

142 PUSH_NULL
144 LOAD_NAME 8 (print)
146 LOAD_CONST 10 ("Access Granted! Here is your flag:")
148 LOAD_NAME 6 (flag)
150 CALL 2
152 POP_TOP

154 RETURN_CONST 1 (None)

156 PUSH_NULL
158 LOAD_NAME 8 (print)
160 LOAD_CONST 11 ("Access Denied! You are ")
162 LOAD_NAME 15 (difference)
164 FORMAT_VALUE 0
166 LOAD_CONST 12 (" away from the correct password. Try again!")
168 BUILD_STRING 3
170 CALL 1
172 POP_TOP

174 LOAD_NAME 9 (i)
176 LOAD_CONST 7 (1)
178 BINARY_OP 0 (+)
180 STORE_NAME 9 (i)

182 JUMP_BACKWARD 91 (to 74)

0 LOAD_GLOBAL 1 (NULL + random)
2 LOAD_ATTR 2 (getrandbits)
4 LOAD_CONST 1 (32)
6 CALL 1
8 LOAD_FAST 0 (i)
10 LOAD_CONST 2 (195894762)
12 BINARY_OP 12 (^)
14 LOAD_CONST 3 (322420958)
16 BINARY_OP 12 (^)
18 BINARY_OP 5 ()
20 LOAD_CONST 4 (2969596945L)
22 BINARY_OP 5 ()
24 STORE_FAST 1 (password)

26 LOAD_FAST 1 (password)
28 RETURN_VALUE```
````

On connecting to the server, we are asked to input a number and if wrong, it will let us know how "away" we were from the correct password, there doesn't seem to be any limit on the number of times we can attempt it. It uses `getrandbits` and does some `XOR` to get the password. On googling about how we can guess psuedo-random numbers in python, I found this [cool page](https://book.jorianwoltjer.com/cryptography/pseudo-random-number-generators-prng) talking about it.&#x20;

Instead of "reversing" that XOR functions, we can just apply those to our random number generated and give it to the predictor.

```python
import re
from pwn import *
from mt19937predictor import MT19937Predictor

HOST = "chals.bitskrieg.in"
PORT = 7007

def get_diff(conn, attempt):
    conn.sendlineafter(b"> ", str(attempt).encode())
    resp = conn.recvline().decode().strip()
    if "Access Denied" in resp:
        diff = int(resp.split(" ")[4])
        return diff
    else:
        print("[-] Weird: ", resp)
        return None

def main():
    predictor = MT19937Predictor()
    conn = remote(HOST, PORT)
    
    i = 1
    while i <= 624:
        diff = get_diff(conn, 0)
        x = (i ^ 195894762) ^ 322420958
        factor = x * 2969596945
        predictor.setrandbits(diff & 0xffffffff, 32)
        i += 1
    
    predicted = predictor.getrandbits(32)
    
    x_625 = (625 ^ 195894762) ^ 322420958
    factor_625 = x_625 * 2969596945
    passwd = predicted * factor_625
    
    print(f"[+] Password: {passwd}")
    
    conn.sendline(str(passwd).encode())
    while True:
        resp = conn.recvline().decode().strip()
        print(resp)
        if "flag" in resp:
            break
    
    conn.close()

if __name__ == "__main__":
    main() 
```

## Reversing Mishaps

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Only 6 solves, Unfortunately I didn't look into this one, so I'll update this and link to others who have written about it.
