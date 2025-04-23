# Forensics

Unfortunately I did had some trouble with other challenges with my volatility. I really wish I had more time to do these challenges, they were quite fun.

## A New Hire - Very Easy

Downloading & extracting the file, we receive an email.eml file, printing  it, it seems like an email which talks about selection for a new position and the link to resume. It clearly says the resume can be found on `/index.php`

<figure><img src="../../.gitbook/assets/image (44).png" alt=""><figcaption></figcaption></figure>

We can check this out using curl, it shows some generic details on the page ,and something being run in a script tag.&#x20;

<figure><img src="../../.gitbook/assets/image (45).png" alt=""><figcaption></figcaption></figure>

Going to that link , we see a resume.lnk file. Downloading and printing it, we can see some powershell command which runs a base64 encoded string

<figure><img src="../../.gitbook/assets/image (46).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (47).png" alt=""><figcaption></figcaption></figure>

base64 decoding the command shows us that it is trying to run a python code. we can see the link to that python code&#x20;

<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

printing the python code, it shows a really huge base64 encoded character and another base64 encoded key. The code purposefully had syntax errors, probably meaning that we don't have to look further?. We get the flag by base64 decoding the key.

<figure><img src="../../.gitbook/assets/image (49).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (50).png" alt=""><figcaption></figcaption></figure>

Flag: `HTB{4PT_28_4nd_m1cr0s0ft_s34rch=1n1t14l_4cc3s!!}`

## Thorin's Amulet - Very Easy

Downloading the file, we are given a powershell file artifact.ps1, looking into it , it runs a base64 encoded command. Decoding that gives us another command which downloads from the `/update` endpoint.

<figure><img src="../../.gitbook/assets/image (51).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (52).png" alt=""><figcaption></figcaption></figure>

We can use curl to fetch the same endpoint, we get another powershell script that does something similar to its parents.

<figure><img src="../../.gitbook/assets/image (53).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (54).png" alt=""><figcaption></figcaption></figure>

We can use powershell to do the same thing and print the string and we get the flag.

<figure><img src="../../.gitbook/assets/image (55).png" alt=""><figcaption></figcaption></figure>

Flag: `HTB{7h0R1N_H45_4lW4Y5_833n_4N_9r347_1NV3n70r}`

