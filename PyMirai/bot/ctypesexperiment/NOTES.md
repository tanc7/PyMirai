To use CTypes, one must convert a C file into a .so shared library file. https://stackoverflow.com/questions/5081875/ctypes-beginner

Also relative paths do not work in CTypes, you must state the absolute path with the command <code>ls $PWD/testfile.so</code>

Then with a Python wrapper, you can manually call the individual functions, class objects, and methods.

Basically operate the botnet inside of the bits and guts of the code.


# The Faux-Reversal Phase

During the Faux-Reversal Phase, individual functions within the original Mirai code could be validated this way. Note that the original code generates warnings in gcc so you need to use suppress warnings -w option.

<code>gcc -shared -Wl,-soname,testlib -o testlib.so -fPIC testlib.c -w</code>

Meanwhile in the event that some exotic method has never been delved with in Python's vast module repositories, then we can rely on CTypes to borrow methods from the original developer's code.

However, the goal is a full and complete and true reversal of Mirai into Python, and we should avoid resorting to C by all means necessary.

