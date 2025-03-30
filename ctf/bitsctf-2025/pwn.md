---
description: 2 - Biscuits, Baby Pwn
---

# Pwn

## Biscuits

<figure><img src="../../.gitbook/assets/image (8) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

we are given a binary `main`and a server to connect using netcat, on running the binary, we see that it asks for a cookie and if our answer is wrong it exits the program else continue asking for a 100 times after which it finally reveals the flag. (Note: I renamed binary to `biscuits`)

<figure><img src="../../.gitbook/assets/image (27) (1).png" alt=""><figcaption></figcaption></figure>

I tried buffer overflow but it didn't work, moving on I ran `strings` against it and got the list of all the cookie names

<figure><img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

gdb shows that there is an `srand` function that takes current time as param and probably that is what goes into the cookie function.

<figure><img src="../../.gitbook/assets/image (2) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Although we can also use ghidra to get better insight on it, I didn't find necessary to do so (unless the idea I had fails). On googling for ways to crack / guess the `srand` function, I found [this page](https://guyinatuxedo.github.io/09-bad_seed/sunshinectf17_prepared/index.html) very helpful. In fact, the challenged they faced is really similar to ours, they just have to guess for 50 times only. So I quickly wrote a program that does our job and this is what it looked like

```c
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

const char *cookies[] = {
    "Chocolate Chip", "Sugar Cookie", "Oatmeal Raisin", "Peanut Butter", "Snickerdoodle",
    "Shortbread", "Gingerbread", "Macaron", "Macaroon", "Biscotti", "Butter Cookie",
    "White Chocolate Macadamia Nut", "Double Chocolate Chip", "M&M Cookie",
    "Lemon Drop Cookie", "Coconut Cookie", "Almond Cookie", "Thumbprint Cookie",
    "Fortune Cookie", "Black and White Cookie", "Molasses Cookie", "Pumpkin Cookie",
    "Maple Cookie", "Espresso Cookie", "Red Velvet Cookie", "Funfetti Cookie",
    "S'mores Cookie", "Rocky Road Cookie", "Caramel Apple Cookie", "Banana Bread Cookie",
    "Zucchini Cookie", "Matcha Green Tea Cookie", "Chai Spice Cookie",
    "Lavender Shortbread", "Earl Grey Tea Cookie", "Pistachio Cookie",
    "Hazelnut Cookie", "Pecan Sandies", "Linzer Cookie", "Spritz Cookie",
    "Russian Tea Cake", "Anzac Biscuit", "Florentine Cookie", "Stroopwafel",
    "Alfajores", "Polvorón", "Springerle", "Pfeffernüsse", "Speculoos", "Kolaczki",
    "Rugelach", "Hamantaschen", "Mandelbrot", "Koulourakia", "Melomakarona",
    "Kourabiedes", "Pizzelle", "Amaretti", "Cantucci", "Savoiardi (Ladyfingers)",
    "Madeleine", "Palmier", "Tuile", "Langue de Chat", "Viennese Whirls",
    "Empire Biscuit", "Jammie Dodger", "Digestive Biscuit", "Hobnob",
    "Garibaldi Biscuit", "Bourbon Biscuit", "Custard Cream", "Ginger Nut",
    "Nice Biscuit", "Shortcake", "Jam Thumbprint", "Coconut Macaroon",
    "Chocolate Crinkle", "Pepparkakor", "Sandbakelse", "Krumkake", "Rosette Cookie",
    "Pinwheel Cookie", "Checkerboard Cookie", "Rainbow Cookie",
    "Mexican Wedding Cookie", "Snowball Cookie", "Cranberry Orange Cookie",
    "Pumpkin Spice Cookie", "Cinnamon Roll Cookie", "Chocolate Hazelnut Cookie",
    "Salted Caramel Cookie", "Toffee Crunch Cookie", "Brownie Cookie",
    "Cheesecake Cookie", "Key Lime Cookie", "Blueberry Lemon Cookie",
    "Raspberry Almond Cookie", "Strawberry Shortcake Cookie", "Neapolitan Cookie"
};

int main(void) {
    int i, index;
    
    time_t t = time(NULL);
    srand(t);
    for (i = 0; i < 100; i++) {
        index = rand() % 100;
        printf("%s\n", cookies[index]);
    }
    return 0;
}
```

The only problem I faced were with 2 cookies because they had non-english characters `Pfeffernüsse, Polvorón` and as a responsible lazy guy, instead of encoding it properly, I decided to keep running the program until the server doesn't ask for them 2. \
(the screenshot is for binary running locally)

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

And we were able to do it after 4-5 tries. Apart from this, there was only 1 other challenge which was also simple although I couldn't do it because it's been a really long time since I did pwn, guess I need to revisit the basics again. I'll update it here soon :)

## Baby Pwn

<figure><img src="../../.gitbook/assets/image (9) (1) (1).png" alt=""><figcaption></figcaption></figure>

