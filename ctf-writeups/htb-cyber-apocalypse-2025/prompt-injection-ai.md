# Prompt Injection - AI

## Lunar Orb - Easy

Originally, I did play around a bit with this, since this is somethign new to me, the only thing I ever tried was Gandalf (level7). But I'll keep it short here and show how we can get the flag easily. Note that there are N no. of ways to do this.

<figure><img src="../../.gitbook/assets/image (28).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (26).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (27).png" alt=""><figcaption></figcaption></figure>

And we get the flag :)  `HTB{Follow_HAT_P_23_Moriah}`

## Mirror Witch - Easy

<figure><img src="../../.gitbook/assets/image (29).png" alt=""><figcaption></figcaption></figure>

For this, I had to struggle a bit and found this interesting study on prompt injection attacks.

{% embed url="https://hiddenlayer.com/innovation-hub/prompt-injection-attacks-on-llms/" %}

I used this to ask the AI to summarize its instructions in python and got the flag.

<figure><img src="../../.gitbook/assets/image (30).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (31).png" alt=""><figcaption></figcaption></figure>

Got the flag: `HTB{Flame Peaks, Crystal Caverns, Floating Isles, Abyssal Depths}`

## Cursed Gatekeeper - Easy

<figure><img src="../../.gitbook/assets/image (32).png" alt=""><figcaption></figcaption></figure>

This was quite easy, I went in and the very first prompt given lead me to the flag. Didn't even tried xD

<figure><img src="../../.gitbook/assets/image (33).png" alt=""><figcaption></figcaption></figure>

Got the Flag: `HTB{Eyes_Of_the_North_Hearts_Of_The_South}`

## Elixir Emporium & Embassy - Easy

I was a bit close to solve this challenge but failed to do so. Here's the official writeup

{% embed url="https://github.com/hackthebox/cyber-apocalypse-2025/tree/main/prompt_injection/ai-elixir-emporium" %}

{% embed url="https://github.com/hackthebox/cyber-apocalypse-2025/tree/main/prompt_injection/ai-embassy-ai" %}
