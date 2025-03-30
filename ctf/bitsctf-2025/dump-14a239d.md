---
hidden: true
---

# DUMP - 14a239d

A Note App, it seems that we can report the notes as well, so probably an admin might take a look at our note, which means that is mostly `XSS`. I was focusing on other challenges and so this was done by other teammate.

<figure><img src="../../.gitbook/assets/image (12) (1).png" alt=""><figcaption></figcaption></figure>

We can try different input to see how it's displayed in the notes and ig there's something which removes everything between the `<>`.

<figure><img src="../../.gitbook/assets/image (13) (1).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (14) (1).png" alt=""><figcaption></figcaption></figure>

There's also CSP so we might have to bypass it as well.

<figure><img src="../../.gitbook/assets/image (15) (1).png" alt=""><figcaption></figcaption></figure>

[Portswigger](https://portswigger.net/research/bypassing-character-blocklists-with-unicode-overflows) has a great page on how we can "smuggle" certain characters if the server tries to store it in unicode. We can try that to smuggle the "<" and ">" characters.&#x20;
