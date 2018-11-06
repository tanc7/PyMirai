for cfile in $(ls *.c)
	do ctopy < $cfile > $cfile.py
	done
