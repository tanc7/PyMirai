# We are on Faux-Reversal Stage

As of right now, this is not a real true-reversal of the Mirai botnet code. Rather, it's a Faux-Reversal of the original C language.

I did this to get a better understanding of the developer's mindset. And realized that a majority of his solutions are mostly "homebrew" (we as Python developers have standardized importable modules installable via PyPi or Pip)

If you imported ctypes and some other modules and ran the code, the bot would work just fine.

# Standards for true reversal

1. Needs to be natively Python, no ctypes or any other language
2. Needs to properly use Pythonic equivalents of the C libraries that the developer of the Mirai botnet used (he created his own toolkits to permit him to modify packets in transit and negotiate networking sessions)
3. Needs to no longer depend on "header.h" files. The majority of the toolkits and/or initialized classes and functions in the original code were located in both the header files, and some of the .c files.
4. Needs to be properly organized in a Pythonic fashion, no dashes in the filenames (underscore instead), libraries should be a central repository of reused code and imported functions, classes, and methods
