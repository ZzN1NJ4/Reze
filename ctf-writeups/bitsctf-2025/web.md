---
description: 4 - Baby Web , Get into my cute small planner , Broken Code , Quantom Paradox
---

# Web

## Baby Web

<figure><img src="../../.gitbook/assets/image (4) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

This is what we see when visiting the website, It seems that we can have login as any user and the password doesn't seem to matter. Later, I also tried having a password given manually using burp.

<figure><img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

When clicked on "Access Admin Area", it tries fetching the `/admin` endpoint and passes that jwt in the Authorization header. Ofcourse it gives `Forbidden` . Now I could guess this is probably something to do with jwt, but before that I'll have a look at the source code and there I found something interesting.&#x20;

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

we do see the `/public-key` endpoint, so we have the public key as well. This could be a jwt confusion attack. I tried loading that in jwt.io and this is what I see.&#x20;

<figure><img src="../../.gitbook/assets/image (2) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

For the jwt confusion attack, we have to change the algorithm and sign the key with the public key which we have (look at [portswigger labs](https://portswigger.net/web-security/jwt/algorithm-confusion)). I manually get the public key and use it to sign our jwt after changing the role back to `admin`.&#x20;

<figure><img src="../../.gitbook/assets/image (4) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (5) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Now we have everything we need, (Note that our key is in base64 so we have to check the checkbox) I can manually use curl to get the flag.

<figure><img src="../../.gitbook/assets/image (6) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

## Get into my cute small planner

<figure><img src="../../.gitbook/assets/image (11) (1).png" alt=""><figcaption></figcaption></figure>

A Note App, it seems that we can report the notes as well, so probably an admin might take a look at our note, which means that is mostly `XSS`. I was focusing on other challenges and so this was done by other teammate. I'll share the writeup soon

## Broken Code

<figure><img src="../../.gitbook/assets/image (16) (1).png" alt=""><figcaption></figcaption></figure>

## Quantum Paradox

<figure><img src="../../.gitbook/assets/image (17) (1).png" alt=""><figcaption></figcaption></figure>

YEAH , 0 Solves, there was only this one small file `processor.wasm` and not sure how is this supposed to help? I'll add the writeup when we receive the official writeup for this

<figure><img src="../../.gitbook/assets/image (18) (1).png" alt=""><figcaption></figcaption></figure>



