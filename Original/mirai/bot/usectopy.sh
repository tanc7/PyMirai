for cfile in $(ls *.h)
	do ctopy < $cfile > $cfile.header.py
	done
