import os
#pragma once

#include <unistd.h>
#include <stdint.h>
#include <stdarg.h>

STDIN	= 0
STDOUT	= 1
STDERR	= 2

False	= 0
True	= 1
typedef BOOL

typedef ipv4_t
typedef port_t

def INET_ADDR(o1,o2,o3,o4):	return (htonl((o1 << 24) | (o2 << 16) | (o3 << 8) | (o4 << 0)))

SINGLE_INSTANCE_PORT	= 48101

FAKE_CNC_ADDR	= INET_ADDR(65,222,202,53)
FAKE_CNC_PORT	= 80

CNC_OP_PING	= 0x00
CNC_OP_KILLSELF	= 0x10
CNC_OP_KILLATTKS	= 0x20
CNC_OP_PROXY	= 0x30
CNC_OP_ATTACK	= 0x40

ipv4_t LOCAL_ADDR

#ifdef DEBUG
static outptr
def xputc(c):
	if outptr:
		*outptr++ = (unsigned char)c
		return
	else:
		os.write(0, &c, 1)

def xputs(const str):
	while *str:
		xputc(*str++)

def xvprintf(const fmt, va_list arp):
	unsigned r, i, j, w, f
	unsigned v
	while True:
		c = *fmt += 1					# Get a char 
		if not c: break				# End of format? 
		if c != '%':				# Pass through it if not a % sequense 
			xputc(c); continue
		f = 0
		c = *fmt += 1					# Get first char of the sequense 
		if c == '0':				# Flag: '0' padded 
			f = 1; c = *fmt += 1
		else:
			if c == '-':			# Flag: left justified 
				f = 2; c = *fmt += 1
		for (w = 0; c >= '0' and c <= '9'; c = *fmt++)	# Minimum width 
			w = w * 10 + c - '0'
		if c == 'l' or c == 'L':	# Prefix: Size is long int 
			f |= 4; c = *fmt += 1
		if not c: break				# End of format? 
		d = c
		#toupper
		if d >= 'a': d -= 0x20
		switch d:				# Type is... 
		case 'S' :					# String 
			p = va_arg(arp, )
			for (j = 0; p[j]; j++) 
			while not (f & 2) and j++ < w) xputc(' ':
			xputs(p)
			while j++ < w) xputc(' ':
			continue
		case 'C' :					# Character 
			xputc((char)va_arg(arp, int)); continue
		case 'B' :					# Binary 
			r = 2; break
		case 'O' :					# Octal 
			r = 8; break
		case 'D' :					# Signed decimal 
		case 'U' :					# Unsigned decimal 
			r = 10; break
		case 'X' :					# Hexdecimal 
			r = 16; break
		default:					# Unknown type (passthrough) 
			xputc(c); continue

		# Get an argument and put it in numeral 
		v = (f & 4) ? va_arg(arp, long) : ((d == 'D') ? (long)va_arg(arp, int) : (long)va_arg(arp, unsigned int))
		if d == 'D' and (v & 0x80000000):
			v = 0 - v
			f |= 8
		i = 0
		while True:
			d = (char)(v % r); v /= r
			if d > 9) d += (c == 'x': ? 0x27 : 0x07
			s[i++] = d + '0'
		    if not (v and i < sizeof(s)): break	# DO-WHILE TERMINATOR -- INDENTATION CAN BE WRONG
		if f & 8: s[i++] = '-'
		j = i; d = (f & 1) ? '0' : ' '
		while not (f & 2) and j++ < w) xputc(d:
		do xputc(s[--i]); while i:
		while j++ < w) xputc(' ':

def xprintf(const fmt, ...):
	va_list arp
	va_start(arp, fmt)
	xvprintf(fmt, arp)
	va_end(arp)
printf	= xprintf

#endif

