---
hidden: true
---

# IAT Camouflage

First we need to follow the steps in [CRT Independent Malware](../crt-independent-malware.md) as they go hand in hand.

Then finally disable code optimization from the visual studio settings -> C/C++ ->  Optimization -> set to Disabled.

Lastly, have some generic WinAPIs in your code / dead code / unreachable code and they should show up in your IAT.

