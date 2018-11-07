import ctypes

loc = "/root/pymirai/PyMirai/bot/ctypesexperiment/testlib.so"
testlib = ctypes.CDLL(loc)
testlib.myPrint()
