This is my efforts of reverse-engineering the Mirai botnet source code into Python. It's been two years since the original launch of the botnet and since that time I have yet to see anyone attempt to completely reverse engineer it outside of making it modified in it's native C and Go programming languages.

My reasons for reversing it into Python is simple

1. To improve it's adaptability in countering cybersecurity measures (by out-adapting the efforts of software engineers)
2. To add the function of "modulettes" that can be installed to further expand the original source code's capabilities

# As of right now a incomplete project

Because of that a notable amount of the code is still in it's native C language, with a hastily and sloppily put together Pythonic equivalent that may or may not work. But...

1. Python is based on C, in fact, your .pyc files are generated containing C code each time it is run
2. For every library and module in C, there is almost assuredly, a equivalent module in Python for example, <code>#include <sys/socket.h></code> versus <code>import socket</code>
3. The original author makes extensive use of the struct structure, commonly misinterpreted as "a Class", when in fact, it can mean something else entirely (like a list, dictionary, or list of methods)

Just because I cooked up together a Pythonic equivalent of the code, it is not reflective of my understanding of it and it may not work. Hence, the code must be revised and migrated into the higher-level programming environment of Python.

But thankfully, since Mirai is originally written in C, direct translation of the code into Python should be fairly painless.
