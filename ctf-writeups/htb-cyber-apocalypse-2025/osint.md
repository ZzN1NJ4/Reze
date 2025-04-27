# OSINT

I managed to do all of the OSINT challenges apart from 1 (the hillside haven). The challenges were quite fun and weren't as difficult as the other categories (apart from only 1 ^).

## Echoes in the Stone - Very Easy

<figure><img src="../../.gitbook/assets/image (1) (1) (1).png" alt=""><figcaption><p>challenge description</p></figcaption></figure>

So the challenge is to find the cross and have the flag as it's name. Downloading the files, I see a jpg file, opening it gives this&#x20;

<figure><img src="../../.gitbook/assets/image (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

I searched for this image on Yandex and quickly found this&#x20;

<figure><img src="../../.gitbook/assets/image (2) (1).png" alt=""><figcaption><p>Searching on Yandex</p></figcaption></figure>

Got the flag: `HTB{Muiredach_High_Cross}`

## The stone that whispers - Very Easy

<figure><img src="../../.gitbook/assets/image (3) (1).png" alt=""><figcaption></figcaption></figure>

Again, we have another object / stone and we need to find its name. Downloading the image, we see this&#x20;

<figure><img src="../../.gitbook/assets/image (4) (1).png" alt=""><figcaption></figcaption></figure>

Searching on Yandex, I see this&#x20;

<figure><img src="../../.gitbook/assets/image (5).png" alt=""><figcaption></figcaption></figure>

Seems like a place Hills of Tara in Ireland but that's the name of the place. We want the name of the stone so I did googled for the name and got the flag.

<figure><img src="../../.gitbook/assets/image (6).png" alt=""><figcaption></figcaption></figure>

Flag: `HTB{Lia_Fail}`

## The Mechanical Bird's Nest - Easy

<figure><img src="../../.gitbook/assets/image (7).png" alt=""><figcaption></figcaption></figure>

This was an interesting one, I did enjoy this. Downloading the image, I see this&#x20;

<figure><img src="../../.gitbook/assets/image (8).png" alt=""><figcaption></figcaption></figure>

Searching for similar images on Yandex, I see a quite interesting name: **Area 51**. Which was weird because I thought that It was blocked by google maps, turns out that they had recently allowed them to get the aerial view.

<figure><img src="../../.gitbook/assets/image (9).png" alt=""><figcaption></figcaption></figure>

Okay so I went to google maps and searched for Area 51. I was aware this was going to be a manual search in the area. So I looked up for Area 51 on the map

<figure><img src="../../.gitbook/assets/image (10).png" alt=""><figcaption></figcaption></figure>

Since the image given to us was zoomed, I tried to have similar level of zoom (a bit zoomed out but not too much) and was searching for the helicopter for a while. After randomly searching, I thought that the 4 hangars at the top would be a good start and decided to go through everything from the top to bottom. Fortunately, The helicopter was really close to that place.

<figure><img src="../../.gitbook/assets/image (12).png" alt=""><figcaption></figcaption></figure>

Zooming on it and clicking on the helicopter , we get the co-ordinates and the flag.

<figure><img src="../../.gitbook/assets/image (13).png" alt=""><figcaption></figcaption></figure>

Flag: `HTB{37.247_-115.812}`

## The Ancient Citadel - Medium

<figure><img src="../../.gitbook/assets/image (14).png" alt=""><figcaption></figcaption></figure>

> Deep in her sanctum beneath Eldoria's streets, Nyla arranges seven crystalline orbs in a perfect circle. Each contains a different vision of stone battlements and weathered walls—possible matches for the mysterious fortress the Queen seeks in the southern kingdoms of Chile. The image in her central crystal pulses with ancient power, showing a majestic citadel hidden among the distant Chilean mountains. Her fingers dance across each comparison crystal, her enchanted sight noting subtle architectural differences between the visions. The runes along her sleeves glow more intensely with each elimination until only one crystal remains illuminated. As she focuses her magical threads on this final vision, precise location runes appear in glowing script around the orb. Nyla smiles in satisfaction as the fortress reveals not just its position, but its true name and history. A more challenging mystery solved by Eldoria's premier information seeker, who knows that even the most distant fortifications cannot hide their secrets from one who compares the patterns of stone and shadow.> \
> HTB{street\_number\_exactzipcode\_city\_with\_underscores\_region}> \
> Example: HTB{Libertad\_102\_2520000\_Viña\_del\_Mar\_Valparaíso} Use underscores between words and include special characters where appropriate

Alright, So this time we need to find this place, some kind of citadel and give the exact location as the flag. I downloaded the files and got this image

<figure><img src="../../.gitbook/assets/image (15).png" alt=""><figcaption></figcaption></figure>

Ok, this seems some kind of castle of old times, there are a few things to note as in the 104 on the gate, the two trees on both the sides of the gate, and the gate design. Initially when I uploaded the image on Yandex, I couldn't find anything of use apart from this picture of a palace. Since the architecture was similar I did took a note of it.

<figure><img src="../../.gitbook/assets/image (16).png" alt=""><figcaption><p><a href="https://id.foursquare.com/v/palacio-presidencial-de-cerro-castillo/4db23ecd8154eb510de61807/photos">Foto di Palacio Presidencial de Cerro Castillo - Callao</a></p></figcaption></figure>

Visiting that website gave me a lot of different pictures related to palaces. Moving On, I decided to switch and use google for the analysis. Although I did thought of only analysing the part of imagee (like the gate) etc but then I wanted to try google this time. Google did led me to an interesting facebook page and also some other website having an image of what seems like this palace.

<figure><img src="../../.gitbook/assets/image (17).png" alt=""><figcaption></figcaption></figure>

The facebook page lead me back to the palace pictures website from Yandex. From the other page, I got a name and searching for it on the map, I finally found the palace.

<figure><img src="../../.gitbook/assets/image (19).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (18).png" alt=""><figcaption><p>Facebook shows similar images but I couldn't see the actual name </p></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (20).png" alt=""><figcaption><p>Castillo Brunet</p></figcaption></figure>

There we can see those 2 trees. Moving forward, I could also confirm the gate number & the exact place from where the challenge image was taken. Then getting the flag was quite simple.

<figure><img src="../../.gitbook/assets/image (21).png" alt=""><figcaption></figcaption></figure>

Flag: `HTB{Iberia_104_2571409_Viña_del_Mar_Valparaíso}`

## The Shadow Sigil - Medium

<figure><img src="../../.gitbook/assets/image (22).png" alt=""><figcaption></figcaption></figure>

> In the central chamber of Eldoria's Arcane Archives, Nyla studies a glowing sigil captured by the royal wardens. The ethereal marking—"139.5.177.205"—pulsates with malicious energy, having appeared in multiple magical breaches across the realm. Her fingers trace the sigil's unique pattern as her network of crystals begins to search through records of known dark covens and their magical signatures. The runes along her sleeves flash with recognition as connections form between seemingly unrelated incidents. Each magical attack bears the same underlying pattern, the same arcane origin. Her enchanted sight follows the magical threads backward through time and space until the name of a notorious cabal of shadow mages materializes in glowing script. Another dangerous secret revealed by Eldoria's master information seeker, who knows that even the most elusive malefactors leave traces of their magic for those skilled enough to recognize their unique signature.> \
> HTB{APTNumber}> \
> Example: HTB{APT01} No special characters

This one was quite easy, like I didn't even feel it should be medium. It was one google search away. (Also its just possible to brute force the answer which I think some of the people did)

Anyways, looking for that ip on google, we get the answer.

<figure><img src="../../.gitbook/assets/image (23).png" alt=""><figcaption></figcaption></figure>

I do realize that searching this again, I didn't see the page (which is weird?). But we can still see it by updating our search to `"139.5.177.205"` .

<figure><img src="../../.gitbook/assets/image (25).png" alt=""><figcaption></figcaption></figure>

## The Hillside Haven

This challenge was quite tough and was probably the one on which I had spent most of my time on. I'll leave a link to the official writeup here for anyone to refer.

{% embed url="https://github.com/hackthebox/cyber-apocalypse-2025/tree/main/OSINT/The%20Hillside%20Haven" %}
