# PyMirai - The Mirai Botnet Source Code in Python

# This is a ongoing project! Nothing is final!

This is my efforts of reverse-engineering the Mirai botnet source code into Python. It's been two years since the original launch of the botnet and since that time I have yet to see anyone attempt to completely reverse engineer it outside of making it modified in it's native C and Go programming languages.

My reasons for reversing it into Python is simple

1. To improve it's adaptability in countering cybersecurity measures (by out-adapting the efforts of software engineers)
2. To add the function of "modulettes" that can be installed to further expand the original source code's capabilities
3. To help propagate the increasing number of Mirai copycats and variants by giving it a better platform to code on (debatable I know, other candidates include Ruby on RAILS, Java, etc.)
4. To add alternatives to the original botnet's C2 platform, that is, a alternative to Google GoLang, such as a Django-hosted server or something connected to a interactive JQuery/REACT Front-End to make it more usable to the end-user


# As of right now a incomplete project

Because of that a notable amount of the code is still in it's native C language, with a hastily and sloppily put together Pythonic equivalent that may or may not work. But... and this is why I expect rollout of a workable PyMirai to be fairly speedy...

1. Python is based on C, in fact, your .pyc files are generated containing C code each time it is run
2. For every library and module in C, there is almost assuredly, a equivalent module in Python for example, <code>#include <sys/socket.h></code> versus <code>import socket</code> and <code> socket(AF_INET,SOCK_STREAM,0) </code> is the same as <code> socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
3. The original author makes extensive use of the struct structure, commonly misinterpreted as "a Class", when in fact, it can mean something else entirely (like a list, dictionary, or list of methods)
4. In my experience, ctopy is a terrible converter of C code to Python. A immediate evaluation after running <code> ctopy < file.c > file.c.py</code> shows that...
		a. The app failed to convert #include to import modules
		b. The whitespace is completely ruined
		c. Functions are not properly being called or declared
		d. Methods are not properly being referred or utilized
		e. Modules often fail to automatically find a equivalent (for example, for the resolv module, we can make use of Python-DNS)
5. There is quite a bit of odd programming logic and methods by the original author of Mirai, however, we do know he wrote it fairly hastily and didn't even consider it himself to be grade A work, but it worked for him. 
6. I seek to rectify and implement my own improvements (for example, togglable wordlists auto-converted into bytecode instead of a standard static 20-word combo wordlist would be a good start)



Just because I cooked up together a Pythonic equivalent of the code, it is not reflective of my understanding of it and it may not work. Hence, the code must be revised and migrated into the higher-level programming environment of Python.

But thankfully, since Mirai is originally written in C, direct translation of the code into Python should be fairly painless.
