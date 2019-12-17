#!/usr/bin/python

# Note: As of 2019, this script will run both in python2 and python3

# Copyright (c) 2006-2007,2019 Sam Trenholme
# 
# TERMS
# 
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 
# This software is provided 'as is' with no guarantees of correctness or
# fitness for purpose.

# This Python script converts a BIND zone file in to a CSV2 zone file

# This program works as a state machine; we have various states and
# convert the input in to the output depending on what state we are in.
# This is not a pure finite state machine, but is one based on the model
# of the CSV2 zone file parser

import sys
import os
import re
import string
from struct import *

ERROR = -1

# We use the compiled regular expressions to determine what input we 
# are getting in a given FSM (finite state machine) state
is_space = re.compile("[ \t]")
is_nonspace = re.compile("[^ \t\r\n]")
is_comment = re.compile("\#[^\n]+$")
is_newline = re.compile("[\r\n]")
is_white = re.compile("[ \t\r\n]")
is_newrec = re.compile("[A-Za-z0-9\-\_\$]")
is_dlabel = re.compile("[A-Za-z0-9\-\_]")
is_number = re.compile("[0-9]")
is_numdot = re.compile("[0-9\.]")
is_hexcolon = re.compile("[0-9a-fA-F\:]")
is_letter = re.compile("[A-Za-z]")
is_pstate = re.compile("paren$")

# This class stores various bits of information we need to look at
# or manipulate while processing the BIND zone file
class buf:
	# Constructor
	def __init__(self):
		self.pre_l = "" # Anything before the dlabel
		self.l = "" # Dlabel of the record we're writing to
		self.thisrr = "" # The current record we're writing to
		self.o = "" # "Write" (for writing things)
		self.s = "" # SOA records; must be at top of CSV2 zone file
		self.n = "" # NS records; must be right after SOA records
		self.rrtype = 3 # 1: SOA RR 2: NS RR 3: Normal RR
		self.rrmode = 1 # Used for Origin/TTL handling 
                                # 1 SOA, 2 NS, 3 Normal RR
		self.lseen = 0 # Whether the label has been seen
		self.origin = "%" # The current origin for this zone
		self.ttl = "" # The current TTL for this zone
		self.norm_ttl = "" # The current TTL for this record
		self.minttl = "86400" # The minimum TTL for this zone
		self.hasttl = 0 # Does this record have an explicit TTL?
		self.soa_hasttl = 0 # Does the SOA record have a TTL?
		self.nsttl = "" # The TTL for the NS records (BIND sets
                                # this to the TTL that the last NS record
				# in a zone has)
		self.isns = 0 # Whether this record is a NS record

	# Add a tilde to the end of the record (Private method)
	def addtilde(self):
		if len(self.thisrr) < 1:
			return	
		while self.thisrr[-1] == " " or self.thisrr[-1] == "\n" or \
                      self.thisrr[-1] == "\t" or self.thisrr[-1] == "\t":
			self.thisrr = self.thisrr[:-1]
			if len(self.thisrr) < 1:
				return
		if is_comment.search(self.thisrr):
			self.thisrr = self.thisrr + "\n"
		else:
			self.thisrr = self.thisrr + " "
		if is_nonspace.search(self.thisrr):
			self.thisrr += "~\n"
		
	# Methods for the current domain label for a given rr
	# Add to label (Public method)
	def label_add(self, a):
		self.lseen = 1
		self.l += a

	# Get label (Public method)
	def label_get(self):
		return self.l

	# Reset label (Public method)
	def label_reset(self):
		self.l = ""

	# Tell the class we have seen the dlabel (Public method)
	def label_seen(self):
		self.lseen = 1

	# Add a character to the area before the Dlabel (private method)
	def pre_write(self, a):
		self.pre_l += a

	# Add a character to the area after the Dlabel (private method)
	def post_write(self, a):
		self.thisrr += a

	# Add a character to the current RR (public method)
	def write(self, a):
		if self.lseen == 0:
			self.pre_write(a)
		else:
			self.post_write(a)

	# Make a character the first character of the default TTL (public)
	def minttl_set(self, a):
		self.minttl = a

	# Add a character to the default TTL (public method)
	def minttl_append(self, a):
		self.minttl += a

	# Make a character the first character of the TTL in a /ttl
	# command (public)
	def slash_ttl_set(self, a):
		self.ttl = a

	# Add a character to the TTL in a /ttl command (public method)
	def slash_ttl_append(self, a):
		self.ttl += a

	# Make a character the first character of the TTL for an ordinary
	# specified TTL (public method)
	def normal_ttl_set(self, a):
		self.norm_ttl = a

	# Add a character to the TTL for an ordinary specified TTL (public)
	def normal_ttl_append(self, a):
		self.norm_ttl += a

	# Make a character the first character of the default origin (public)
	def origin_set(self, a):
		self.origin = a

	# Add a character to the default origin (public method)
	def origin_append(self, a):
		self.origin += a

	# Inform this object that this record has a TTL (public method)
	def hasttl_set(self):
		self.hasttl = 1

	# Inform this object that this record's current record's a SOA,
        # which may set the soa_hasttl flag (public)
	def issoa(self):
		if self.hasttl == 1:
			self.soa_hasttl = 1

	# Process a dcommand that we have received (public method)
	def dcommand_process(self):
		if self.l == "/ttl":
			return "prettl"
		elif self.l == "/origin":
			return "preorigin"
		else:
			print("Unknown directive " + self.l)
			return "error"

	# Add a current RR to a stream (private method)
	def rr_write(self):
		self.addtilde()
		oput = self.pre_l
		# If this is a record that doesn't "belong" here...
		if self.rrmode != self.rrtype:
			# Then the record will need an explicit origin
 			# set if it needs an origin (ends in "%") and
			# an explicit TTL set if the record doesn't
			# have a TTL
			if len(self.l) > 0 and self.l[-1] == "%":
				self.l = self.l[:-1] + origin
			# If this record does not have an explicit TTL...
			if self.hasttl == 0:
				if self.ttl != "":
					self.thisrr = " +" + self.ttl + \
						      " " + self.thisrr
				elif self.soa_hasttl == 0:
					self.thisrr = " +" + self.minttl + \
						      " " + self.thisrr
				else:
					self.thisrr = " +" + self.norm_ttl + \
						      " " + self.thisrr
		# This handles the case of the SOA having a TTL record;
		# in which case the default TTL is the last explicitly
		# set TTL (or $TTL if that has been set)
		elif self.hasttl == 0 and self.soa_hasttl == 1 and \
			self.ttl == "":
				self.thisrr = " +" + self.norm_ttl + \
					" " + self.thisrr
		oput += self.l
		oput += self.thisrr	
		self.thisrr = ""
		self.pre_l = ""
		self.lseen = 0
		self.hasttl = 0
		self.isns = 0
		return oput

	# Add the current RR to the stream of normal RRs (private method)
	def owrite(self):
		self.o += self.rr_write()

	# Add the current RR to the stream of SOA RRs (private method)
	def swrite(self):
		self.s += self.rr_write()

	# Add the current RR to the stream of NS RRs (private method)
	def nwrite(self):
		self.n += self.rr_write()

	# Flush the current RR, adding it to the appropiate stream, and
	# get ready to start a new RR (Public method)
	def flush_rr(self): 
		if is_nonspace.search(self.thisrr):
			if self.rrtype == 1: 
				self.swrite()
			elif self.rrtype == 2: 
				if self.rrmode == 1:
					self.rrmode = 2
				self.nwrite()
			elif self.rrtype == 3: 
				if self.rrmode == 2:
					self.rrmode = 3
				self.owrite()
			else:
				if self.rrmode == 2:
					self.rrmode = 3
				self.owrite()
			self.rrtype = 3

	# Make the current RR a "soa" RR (Public method)
	def set_soa(self):
		self.rrtype = 1

	# Make the current RR a "ns" RR (Public method)
	def set_ns(self):
		self.rrtype = 2

	# Make ths current RR a "normal" RR (Public, unused method)
	def set_normal(self):
		self.rrtype = 3

	# Read all of the three RR streams combined together in to a 
        # full zone file (Public method)
	def read(self):
		if self.soa_hasttl == 0:
			return "/ttl " + self.minttl + " ~\n" + self.s + \
			self.n + self.o
		else:
			return self.s + self.n + self.o

# "Output print"; we give this a short name because this function is
# called so often.  This puts a string on the output tape

def op(o,a):
	o.write(a)

# The actions we do when the finite state machine is in various
# states

# Process a comment
def process_comment(i,o):
	z = 0
	op(o,"#")
	while z < 1000:
		a = i.read(1).decode('utf-8')
		if is_newline.match(a):
			return a
		else:
			op(o,a)
		z += 1
	return a
			
# Based on the rrtype they gave us, determine what state we should be
# in next

def get_rr_type(rrname):
	rrname = rrname.lower()
	if rrname == "in":
		return "error"
	elif rrname == "a":
		return "rr_a"
	elif rrname == "ns":
		return "rr_ns"
	elif rrname == "cname":
		return "rr_1dlabel"
	elif rrname == "ptr":
		return "rr_1dlabel"
	elif rrname == "soa":
		return "rr_soa"
	elif rrname == "mx":
		return "rr_mx"
	elif rrname == "aaaa":
		return "rr_aaaa"
	elif rrname == "srv":
		return "rr_srv"
	elif rrname == "txt":
		return "rr_txt"
	elif rrname == "spf":
		return "rr_txt"
	# Obscure RRs follow
	elif rrname == "hinfo":
		return "rr_txt" # TXT with mandatory two fields
	elif rrname == "wks":
		#return "rr_wks" # Tricky variable-argument corner case
		return "rr_variargs" # I'll just let the csv2 code parse this
	elif rrname == "mb":
		return "rr_1dlabel"
	elif rrname == "md":
		return "rr_1dlabel"
	elif rrname == "mf":
		return "rr_1dlabel"
	elif rrname == "mg":
		return "rr_1dlabel"
	elif rrname == "mr":
		return "rr_1dlabel"
	elif rrname == "minfo":
		return "rr_2dlabels"
	elif rrname == "afsdb":
		return "rr_mx"
	elif rrname == "rp":
		return "rr_2dlabels"
	elif rrname == "x25":
		return "rr_txt"
	elif rrname == "isdn":
		return "rr_txt"
	elif rrname == "rt":
		return "rr_mx"
	elif rrname == "nsap":
		#return "rr_hex"
		return "rr_variargs" # I'll just let the csv2 code parse this
	elif rrname == "px":
		#return "rr_px"
		return "rr_variargs" # I'll just let the csv2 code parse this
	elif rrname == "gpos":
		return "rr_txt" # TXT with three mandatory fields
	elif rrname == "loc":
		#return "rr_loc" # Complicated RR with variable # of fields
		return "rr_variargs" # I'll just let the csv2 code parse this
	else:	
		print("Error: Unknown RR " + rrname)
		return "error"

# Generic handler that handles parenthesis in a zone file
def handle_paren(a,o,state,buffer):
	paren = ""
	if is_pstate.search(state):
		paren = "_paren"
	if paren == "" and is_newline.match(a):
		print("Error: Premature termination of RR")
		return ("error", "", 1, paren)
	if paren == "_paren" and a == "(":
		print("Error: Parens don't nest")
		retrun ("error", "", 1, paren)
	if paren == "" and a == "(":
		op(o," ")
		return (state + "_paren", buffer, 1, paren)
	if paren == "_paren" and a == ")":
		op(o," ")
		paren = ""
		return (state[:-6], buffer, 1, paren)
	return (state,buffer,0,paren)

# Between the rrtype and the rrdata in the zone file
def prrtype(a,o,state,buffer):
	(state, buffer, paren, pstr) = handle_paren(a,o,state,buffer)
	if paren == 1:
		return (state, buffer)
	if is_white.match(a):
		op(o,a)
		return (state,buffer)
	x = get_rr_type(buffer)
	# NS record is a 1-dlabel record we put near the top of the zone
        # file.
	if x == "rr_ns":
		x = "rr_1dlabel"
		o.set_ns()
	# SOA record is a complicated RR type we put at the top of the
        # zone file.
	if x == "rr_soa":
		o.set_soa()
	return (x + pstr, "")
		
# Between the rrdata and the next rr in the zone file
def postrr(a,o,state,buffer):
	if is_newline.match(a) and not is_pstate.search(state):
		# Flush out this RR
		op(o,a)
		o.flush_rr()
		return("pre_rr",buffer)
	if is_white.match(a):
		op(o,a)
		return (state,buffer)
	(state, buffer, paren, pstr) = handle_paren(a,o,state,buffer)
	if paren == 1:
		return (state, buffer)
	print("Error: Unexpected character after RR " + a)
	return("error","")

# After the first non-escaped newline at the end of a rr in the
# zone file
def pre_rr(a,o,state,buffer):
	if is_space.match(a):
		return ("possible_lo",buffer)
	if is_white.match(a):
		op(o,a)
		return (state,buffer)
	elif is_newrec.match(a):
		if a == "$":
			o.label_reset()
			o.label_add("/")
			return ("dcommand",buffer)
		else:
			o.label_reset()
			o.label_add(a)
			return("dlabel",buffer)
	print("Error: Unexpected character before RR " + a)
	return("error","")

# In the whitespace before a default TTL ("/ttl 12345")
def prettl(a,o,state,buffer):
	if is_white.match(a):
		op(o,a)
		return(state, buffer)
	if is_number.match(a):	
		op(o,a)
		o.slash_ttl_set(a)
		return ("sttl", buffer)
	print("Error: unexpected character before TTL " + a)
	return("error","")

# In a default TTL ("/ttl 12345")
def sttl(a,o,state,buffer):
	if is_white.match(a):
		op(o,a)
		return("postrr", buffer)
	if is_number.match(a):	
		op(o,a)
		o.slash_ttl_append(a)
		return ("sttl", buffer)
	print("Error: unexpected character in TTL " + a)
	return("error","")

# In the whitespace before an origin ("/origin foo")
def preorigin(a,o,state,buffer):
	if is_white.match(a):
		op(o,a)
		return(state, buffer)
	if is_dlabel.match(a):	
		op(o,a)
		o.origin_set(a)
		return ("origin", buffer)
	print("Error: unexpected character before origin " + a)
	return("error","")

# In an origin ("/origin foo")
def origin(a,o,state,buffer):
	if is_white.match(a):
		op(o,a)
		return("postrr", buffer)
	if is_dlabel.match(a):	
		op(o,a)
		o.origin_append(a)
		return ("origin", buffer)
	print("Error: unexpected character in origin " + a)
	return("error","")

# After a space at the beginning of an RR and before a newline
def possible_lo(a,o,state,buffer):
	if is_space.match(a):
		return (state,buffer)
	if is_white.match(a):
		return ("pre_rr",buffer)
	# Output the stored dlabel from the last record
	o.label_seen()
	op(o," ")
	if is_number.match(a):
		op(o,"+" + a)
		o.hasttl_set()
		o.normal_ttl_set(a)
		return ("ttl",buffer)
	if is_letter.match(a):
		return ("rrtype",a)      

# After a space at the beginning of an RR and before the TTL/IN/RRTYPE
def post_lo(a,o,state,buffer):
	return (a,o,state,buffer);
		
# In TTL
def ttl(a,o,state,buffer):
	(state, buffer, paren, pstr) = handle_paren(a,o,state,buffer)
	if paren == 1:
		return (state, buffer)
	if is_white.match(a):
		op(o,a)
		return ("pdlabel" + pstr, buffer)
	if is_number.match(a):
		op(o,a)
		o.normal_ttl_append(a)
		return ("ttl" + pstr,buffer)
	print("Unexpected character in TTL " + a)
	return("error","")

# Various handlers for the rr types that we may see

# A: Internet IP address 
def rr_a(a,o,state,buffer):
	pstr = ""
	if is_pstate.search(state):
		pstr = "_paren"
	if is_newline.match(a) and not is_pstate.search(state):
		return ("postrr",buffer)
	if is_white.match(a):
		op(o,a)
		return ("postrr" + pstr,buffer)
	if is_numdot.match(a):
		op(o,a)
		return (state,buffer)	
	print("Error: Unexpected character in A RR " + a)
	return("error","")

# AAAA: Ipv6 Internet IP address 
def rr_aaaa(a,o,state,buffer):
	pstr = ""
	if is_pstate.search(state):
		pstr = "_paren"
	if is_newline.match(a) and not is_pstate.search(state):
		return ("postrr",buffer)
	if is_white.match(a):
		op(o,a)
		return ("postrr" + pstr,buffer)
	if is_hexcolon.match(a):
		op(o,a)
		return (state,buffer)	
	print("Error: Unexpected character in A RR " + a)
	return("error","")

# Generic handler for NS records or anything else that has a single dlabel
def rr_1dlabel(a,o,state,buffer):
	pstr = ""
	if is_pstate.search(state):
		pstr = "_paren"
	if is_newline.match(a) and not is_pstate.search(state):
		return ("postrr",buffer)
	if is_white.match(a):
		# I think BIND zone files require a final dot in dlabels
                # also, or will append the domain name.  If not, this
                # bit of code will change to not have the '+ ".%"'
		op(o,a + ".%")
		return ("postrr" + pstr,buffer)
	if is_dlabel.match(a):
		op(o,a)
		return (state,buffer)
	if a == ".":
		op(o,a)
		return ("rr_1dlabel_dot" + pstr, buffer)
	print("Error: Unexpected character in RR " + a)
	return("error","")

# In the dot (".") of a dlabel	
def rr_1dlabel_dot(a,o,state,buffer):
	pstr = ""
	if is_pstate.search(state):
		pstr = "_paren"
	if is_newline.match(a) and not is_pstate.search(state):
		return ("postrr",buffer)
	# End of RR after dot
	if is_white.match(a):
		op(o,a)
		return ("postrr" + pstr,buffer)
	if is_dlabel.match(a):
		op(o,a)
		return ("rr_1dlabel" + pstr,buffer)
	print("Error: Unexpected character in RR " + a)
	return("error","")

# Generic handlers for dlabels and numbers

# In a dot in a dlabel
def rr_generic_dlabel_dot(a,o,state,buffer,next):
	pstr = ""
	if is_pstate.search(state):
		pstr = "_paren"
	if is_white.match(a):
		op(o,a)
		return(next + pstr, buffer)
	if is_dlabel.match(a):  
		op(o,a)
		if pstr == "_paren":
			return(state[:-10] + pstr, buffer)
		return (state[:-4], buffer)
	print("Error: unexpected character in RR dlabel dot " + a)
	return("error","")

# In the whitespace before a dlabel		
def rr_generic_dlabel_pre(a,o,state,buffer,next):
	(state, buffer, paren, pstr) = handle_paren(a,o,state,buffer)
	if paren == 1:
		return(state, buffer)
	if is_white.match(a):
		op(o,a)
		return(state, buffer)
	if is_dlabel.match(a):	
		op(o,a)
		return (next + pstr, buffer)
	print("Error: unexpected character before RR dlabel " + a)
	return("error","")

# In a dlabel
def rr_generic_dlabel(a,o,state,buffer,next):
	pstr = ""
	if is_pstate.search(state):
		pstr = "_paren"
	if is_white.match(a):
		op(o,".%" + a)
		return(next + pstr, buffer)
	if is_dlabel.match(a):	
		op(o,a)
		return (state, buffer)
	if a == ".":	
		op(o,a)
		if pstr == "_paren":
			return(state[:-10] + "_dot" + pstr, buffer)
		return (state + "_dot", buffer)
	print("Error: unexpected character in RR dlabel " + a)
	return("error","")

# In the whitespace before a number		
def rr_generic_number_pre(a,o,state,buffer,next):
	(state, buffer, paren, pstr) = handle_paren(a,o,state,buffer)
	if paren == 1:
		return(state, buffer)
	if is_white.match(a):
		op(o,a)
		return(state, buffer)
	if is_number.match(a):	
		op(o,a)
		return (next + pstr, buffer)
	print("Error: unexpected character before RR number field " + a)
	return("error","")

# In a number
def rr_generic_number(a,o,state,buffer,next):
	pstr = ""
	if is_pstate.search(state):
		pstr = "_paren"
	if is_white.match(a):
		op(o,a)
		return(next + pstr, buffer)
	if is_number.match(a):	
		op(o,a)
		return (state, buffer)
	print("Error: unexpected character in numer field of RR " + a)
	return("error","")

# In the whitespace before the SOA minimum field
def rr_soa_minimum_pre(a,o,state,buffer,next):
	(state, buffer, paren, pstr) = handle_paren(a,o,state,buffer)
	if paren == 1:
		return(state, buffer)
	if is_white.match(a):
		op(o,a)
		return(state, buffer)
	if is_number.match(a):	
		op(o,a)
		o.minttl_set(a)
		return (next + pstr, buffer)
	print("Error: unexpected character before RR number field " + a)
	return("error","")

# In SOA minimum field
def rr_soa_minimum(a,o,state,buffer,next):
	pstr = ""
	if is_pstate.search(state):
		pstr = "_paren"
	if is_white.match(a):
		op(o,a)
		return(next + pstr, buffer)
	if is_number.match(a):	
		op(o,a)
		o.minttl_append(a)
		return (state, buffer)
	print("Error: unexpected character in numer field of RR " + a)
	return("error","")

# SOA: Start of authority record (2 dlabels, 5 numbers)
def rr_soa(a,o,state,buffer):
	o.issoa()
	return rr_generic_dlabel(a,o,state,buffer,"rr_soa_2_pre")

def rr_soa_dot(a,o,state,buffer):
	return rr_generic_dlabel_dot(a,o,state,buffer,"rr_soa_2_pre")

def rr_soa_2_pre(a,o,state,buffer):
	return rr_generic_dlabel_pre(a,o,state,buffer,"rr_soa_2")

def rr_soa_2(a,o,state,buffer):
	return rr_generic_dlabel(a,o,state,buffer,"rr_soa_3_pre")

def rr_soa_2_dot(a,o,state,buffer):
	return rr_generic_dlabel_dot(a,o,state,buffer,"rr_soa_3_pre")

def rr_soa_3_pre(a,o,state,buffer):
	return rr_generic_number_pre(a,o,state,buffer,"rr_soa_3")

def rr_soa_3(a,o,state,buffer):
	return rr_generic_number(a,o,state,buffer,"rr_soa_4_pre")

def rr_soa_4_pre(a,o,state,buffer):
	return rr_generic_number_pre(a,o,state,buffer,"rr_soa_4")

def rr_soa_4(a,o,state,buffer):
	return rr_generic_number(a,o,state,buffer,"rr_soa_5_pre")

def rr_soa_5_pre(a,o,state,buffer):
	return rr_generic_number_pre(a,o,state,buffer,"rr_soa_5")

def rr_soa_5(a,o,state,buffer):
	return rr_generic_number(a,o,state,buffer,"rr_soa_6_pre")

def rr_soa_6_pre(a,o,state,buffer):
	return rr_generic_number_pre(a,o,state,buffer,"rr_soa_6")

def rr_soa_6(a,o,state,buffer):
	return rr_generic_number(a,o,state,buffer,"rr_soa_7_pre")

def rr_soa_7_pre(a,o,state,buffer):
	return rr_soa_minimum_pre(a,o,state,buffer,"rr_soa_7")

def rr_soa_7(a,o,state,buffer):
	return rr_soa_minimum(a,o,state,buffer,"postrr")

# MX: Mail exchange record (1 number, 1 dlabel)
def rr_mx(a,o,state,buffer):
	return rr_generic_number(a,o,state,buffer,"rr_mx_2_pre")

def rr_mx_pre(a,o,state,buffer):
	return rr_generic_number_pre(a,o,state,buffer,"rr_mx")

def rr_mx_2_pre(a,o,state,buffer):
	return rr_generic_dlabel_pre(a,o,state,buffer,"rr_mx_2")

def rr_mx_2(a,o,state,buffer):
	return rr_generic_dlabel(a,o,state,buffer,"postrr")

def rr_mx_2_dot(a,o,state,buffer):
	return rr_generic_dlabel_dot(a,o,state,buffer,"postrr")

# generic handlers for records with 2 dlabels
def rr_2dlabels(a,o,state,buffer):
	return rr_generic_dlabel(a,o,state,buffer,"rr_mx_2_pre")

def rr_2dlabels_dot(a,o,state,buffer):
	return rr_generic_dlabel_dot(a,o,state,buffer,"rr_mx_2_pre")

# SRV record (3 numbers, 1 dlabel)
def rr_srv(a,o,state,buffer):
	return rr_generic_number(a,o,state,buffer,"rr_srv_2_pre")

def rr_srv_2_pre(a,o,state,buffer):
	return rr_generic_number_pre(a,o,state,buffer,"rr_srv_2")

# Since the last fields of a SRV record are identical to a MX
# record, we can simply jump to the MX record after the second
# SRV field
def rr_srv_2(a,o,state,buffer):
	return rr_generic_number(a,o,state,buffer,"rr_mx_pre")

# Generic handler for obscure RRs, some of which have a variable number
# of arguments (PX, WKS, NSAP, and LOC)

def rr_variargs(a,o,state,buffer):
	if is_newline.match(a) and not is_pstate.search(state):
		return ("postrr",buffer)
	(state, buffer, paren, pstr) = handle_paren(a,o,state,buffer)
	if paren == 1:
		return(state, buffer)
	op(o,a)
	return(state, buffer)
	
# TXT record, outside of quotes

def rr_txt(a,o,state,buffer):
	if is_newline.match(a) and not is_pstate.search(state):
		return ("postrr",buffer)
	(state, buffer, paren, pstr) = handle_paren(a,o,state,buffer)
	if paren == 1:
		return(state, buffer)
	if is_white.match(a):
		op(o,a)
		return(state, buffer)
	if a == "\"":
		return("rr_txt_4" + pstr,buffer)
	print("Error: unexpected character ouside of quotes in TXT RR " + a)
	return("error","")

# rr_txt_2: In TXT record between quotes

def rr_txt_2(a,o,state,buffer):
	pstr = ""
	if is_pstate.search(state):
		pstr = "_paren"
	if(len(a) == 1):
		q = unpack("B",a)[0];
	else:
		print("Error: Unexpected char length in TXT RR " + a)
		return("error","")
	# If q is printable ASCII and q isn't ["#'|~\]
	if q >= 32 and q <= 125 and q != 34 and q != 35 \
	           and q != 39 and q != 124 and q != 92:
		op(o,a)	
	# 34: "
	elif q == 34: 
		op(o,"\'")
		return("rr_txt" + pstr,buffer)
	# 92: \
	elif q == 92:
		return("rr_txt_backslash" + pstr,buffer)
	else:
		op(o,"\'\\x%02x" % q)
		return("rr_txt_3" + pstr,buffer)
	return(state,buffer)

# rr_txt_3: Quoting non-printable characters in a TXT record
def rr_txt_3(a,o,state,buffer):
	pstr = ""
	if is_pstate.search(state):
		pstr = "_paren"
	if(len(a) == 1):
		q = unpack("B",a)[0];
	else:
		print("Error: Unexpected char length in TXT RR " + a)
		return("error","")
	# If q is printable ASCII and q isn't ["#'|~]
	if q >= 32 and q <= 125 and q != 34 and q != 35 \
	           and q != 39 and q != 124 and q != 92:
		op(o,"\'" + a)	
		return("rr_txt_2" + pstr,buffer)
	# 34: "
	elif q == 34: 
		op(o," ")
		return("rr_txt" + pstr,buffer)
	# 92: \ (backslash) 
	elif q == 92:
		op(o,"\'")
		return("rr_txt_backslash" + pstr,buffer)
	else:
		op(o,"\\x%02x" % q)
		return("rr_txt_3" + pstr,buffer)
	return(state,buffer)

# rr_txt_4: Right after opening quote of TXT record

def rr_txt_4(a,o,state,buffer):
	pstr = ""
	if is_pstate.search(state):
		pstr = "_paren"
	if(len(a) == 1):
		q = unpack("B",a)[0];
	else:
		print("Error: Unexpected char length in TXT RR " + a)
		return("error","")
	# If q is printable ASCII and q isn't ["#'|~\]
	if q >= 32 and q <= 125 and q != 34 and q != 35 \
	           and q != 39 and q != 124 and q != 92:
		op(o,"\'" + a)	
		return("rr_txt_2" + pstr,buffer)
	# 34: " (empty TXT field)
	elif q == 34: 
		op(o,"\'\'")
		return("rr_txt" + pstr,buffer)
	# 92: \ (backslash) 
	elif q == 92:
		op(o,"\'")
		return("rr_txt_backslash" + pstr,buffer)
	else:
		op(o,"\\x%02x" % q)
		return("rr_txt_3" + pstr,buffer)
	print("Unexpected error in rr_txt_4")
	return("error","")

# rr_txt_backslash: Right after a backslash in a TXT record
def rr_txt_backslash(a,o,state,buffer):
	pstr = ""
	if is_pstate.search(state):
		pstr = "_paren"
	if is_number.match(a):
		# Use the buffer to store the numeric value
		return("rr_txt_numeric" + pstr,a)
	# Otherwise
	if(len(a) == 1):
		q = unpack("B",a)[0];
	else:
		print("Error: Unexpected char length in TXT RR " + a)
		return("error","")
	# If q is printable ASCII and q isn't [#'|~]
	if q >= 32 and q <= 125 and q != 35 \
	           and q != 39 and q != 124:
		op(o,a)	
	else:
		op(o,"\'\\x%02x" % q)
		return("rr_txt_3" + pstr,buffer)
	return("rr_txt_2" + pstr,buffer)

# rr_txt_numeric: In the middle of a backslashed number
def rr_txt_numeric(a,o,state,buffer):
	pstr = ""
	if is_pstate.search(state):
		pstr = "_paren"
	if is_number.match(a):
		# Use the buffer to store the numeric value
		return("rr_txt_numeric",buffer + a)
	x = buffer 
	if int(x) < 256:
		op(o,"\'\\x%02x\'" % int(x))
	else:
		print("Error: Value of backslashed number " + x + " too high")
		return("error","")
	# Otherwise
	if(len(a) == 1):
		q = unpack("B",a)[0];
	else:
		print("Error: Unexpected char length in TXT RR " + a)
		return("error","")
	# If q is printable ASCII and q isn't [#'|~\]
	if q >= 32 and q <= 125 and q != 35 and q != 34 \
	           and q != 39 and q != 124 and q != 92:
		op(o,a)	
	# 34: "
	elif q == 34: 
		op(o,"\'")
		return("rr_txt" + pstr,buffer)
	else:
		op(o,"\'\\x%02x" % q)
		return("rr_txt_3" + pstr,buffer)
	return("rr_txt_2" + pstr,buffer)

# In rrtype (The "A", "MX", "NS", etc. label)
def rrtype(a,o,state,buffer):
	(state, buffer, paren, pstr) = handle_paren(a,o,state,buffer)
	if paren == 1:
		return (state, buffer)
	if is_dlabel.match(a):
		return (state,buffer + a)
	if is_white.match(a):
		# In the case of "IN", we go back to the state of being
                # after the dlabel, where we look for either a TTL or a 
                # RRTYPE
		if buffer.lower() != "in":
			op(o,buffer)
		else:
			op(o,a)
			return("pdlabel" + pstr, "")
		op(o,a)
		return ("prrtype" + pstr, buffer)
	print("Invalid character in RR type " + a)
	return ("error","")

# After dlabel (name of record we have info for) and before TTL/rrtype
def pdlabel(a,o,state,buffer):
	(state, buffer, paren, pstr) = handle_paren(a,o,state,buffer)
	if paren == 1:
		return (state, buffer)
	if is_white.match(a):
		op(o,a)
		return (state, buffer)
	if is_number.match(a):
		op(o,"+" + a)
		o.hasttl_set()
		o.normal_ttl_set(a)
		return ("ttl" + pstr,buffer)
	if is_letter.match(a):
		return ("rrtype" + pstr,a)	
	print("Unexpected character after dlabel " + a)
	return("error","")

# In a "." character in the dlabel (name of machine we have record for)	
def dlabel_dot(a,o,state,buffer):
	if is_dlabel.match(a):
		o.label_add(a)
		return ("dlabel",buffer)
	elif is_space.match(a):
		op(o,a)
		return ("pdlabel",buffer)
	else:
		print("Unexpected chatacter near dlabel " + a)
		return ("error","")

# In DCommand (a "slash" command like "/ttl" or "/origin")
def dcommand(a,o,state,buffer):
	if is_letter.match(a):
		o.label_add(a.lower())
		return ("dcommand",buffer)
	elif is_space.match(a):
		op(o,a)
		return (o.dcommand_process(),buffer)
	else:
		print("Unexpected chatacter in slash command " + a)
		return ("error","")

# In the dlabel (name of machine we are looking at record for)
def dlabel_s(a,o,state,buffer):
	if is_dlabel.match(a):
		o.label_add(a)
		return (state,buffer)
	elif is_space.match(a):
		o.label_add(".%" + a)
		return ("pdlabel",buffer)
	elif a == ".":
		#op(o,a)
		o.label_add(a)
		return ("dlabel_dot",buffer)
	else:
		print("Unexpected character in dlabel " + a)
		return ("error","")	

# Initial state at beginning of file				
def init_s(a,o,state,buffer):
	if is_white.match(a):
		op(o,a)
		return (state,buffer)
	elif is_newrec.match(a):
		if a == "$":
			o.label_reset()
			o.label_add("/")
			return ("dcommand",buffer)
		else:
			o.label_add(a)
			return("dlabel",buffer)
	else:
		print("Error: Unexpected character at new file start " + a)
		return("error","")
		
# END machine states

# This routine goes to the appropriate routine for the state we are in
def process_char(a,o,state,buffer):
	# print "Char is " + a + " state is " + state # DEBUG

        # Special states (beginning of file, etc)
	if state == "init_state":
		(state, buffer) = init_s(a,o,state,buffer)
	elif state == "dlabel":
		(state,buffer) = dlabel_s(a,o,state,buffer)
	elif state == "dlabel_dot":
		(state,buffer) = dlabel_dot(a,o,state,buffer)
	elif state == "dcommand":
		(state,buffer) = dcommand(a,o,state,buffer)
	elif state == "prettl":
		(state,buffer) = prettl(a,o,state,buffer)
	elif state == "sttl":
		(state,buffer) = sttl(a,o,state,buffer)
	elif state == "preorigin":
		(state,buffer) = preorigin(a,o,state,buffer)
	elif state == "origin":
		(state,buffer) = origin(a,o,state,buffer)
	elif state == "pdlabel" or state == "pdlabel_paren":
		(state,buffer) = pdlabel(a,o,state,buffer)
	elif state == "ttl" or state == "ttl_paren":
		(state,buffer) = ttl(a,o,state,buffer)
	elif state == "rrtype" or state == "rrtype_paren":
		(state,buffer) = rrtype(a,o,state,buffer)
	elif state == "prrtype" or state == "prrtype_paren":
		(state,buffer) = prrtype(a,o,state,buffer)
	elif state == "possible_lo":
		(state,buffer) = possible_lo(a,o,state,buffer)
	# We put an if instead of an elif here because prrtype, when it 
        # hits the first character of the rr, "falls through" since 
        # what we do with the character we see depends on the rrtype
	
	# The A RR
	if state == "rr_a" or state == "rr_a_paren":
		(state,buffer) = rr_a(a,o,state,buffer)

	# Generic handlers for 1 dlabel RRs: NS, CNAME, PTR, and the
	# obscure MB, MD, MF, MG, and MR records
	elif state == "rr_1dlabel" or state == "rr_1dlabel_paren":
		(state,buffer) = rr_1dlabel(a,o,state,buffer)
	elif state == "rr_1dlabel_dot" or state == "rr_1dlabel_dot_paren":
		(state,buffer) = rr_1dlabel_dot(a,o,state,buffer)

	# The SOA RRs
	elif state == "rr_soa" or state == "rr_soa_paren":
		(state,buffer) = rr_soa(a,o,state,buffer)
	elif state == "rr_soa_dot" or state == "rr_soa_dot_paren":
		(state,buffer) = rr_soa_dot(a,o,state,buffer)
	elif state == "rr_soa_2_pre" or state == "rr_soa_2_pre_paren":
		(state,buffer) = rr_soa_2_pre(a,o,state,buffer)
	elif state == "rr_soa_2" or state == "rr_soa_2_paren":
		(state,buffer) = rr_soa_2(a,o,state,buffer)
	elif state == "rr_soa_2_dot" or state == "rr_soa_2_dot_paren":
		(state,buffer) = rr_soa_2_dot(a,o,state,buffer)
	elif state == "rr_soa_3_pre" or state == "rr_soa_3_pre_paren":
		(state,buffer) = rr_soa_3_pre(a,o,state,buffer)
	elif state == "rr_soa_3" or state == "rr_soa_3_paren":
		(state,buffer) = rr_soa_3(a,o,state,buffer)
	elif state == "rr_soa_4_pre" or state == "rr_soa_4_pre_paren":
		(state,buffer) = rr_soa_4_pre(a,o,state,buffer)
	elif state == "rr_soa_4" or state == "rr_soa_4_paren":
		(state,buffer) = rr_soa_4(a,o,state,buffer)
	elif state == "rr_soa_5_pre" or state == "rr_soa_5_pre_paren":
		(state,buffer) = rr_soa_5_pre(a,o,state,buffer)
	elif state == "rr_soa_5" or state == "rr_soa_5_paren":
		(state,buffer) = rr_soa_5(a,o,state,buffer)
	elif state == "rr_soa_6_pre" or state == "rr_soa_6_pre_paren":
		(state,buffer) = rr_soa_6_pre(a,o,state,buffer)
	elif state == "rr_soa_6" or state == "rr_soa_6_paren":
		(state,buffer) = rr_soa_6(a,o,state,buffer)
	elif state == "rr_soa_7" or state == "rr_soa_7_paren":
		(state,buffer) = rr_soa_7(a,o,state,buffer)
	elif state == "rr_soa_7_pre" or state == "rr_soa_7_pre_paren":
		(state,buffer) = rr_soa_7_pre(a,o,state,buffer)

	# The MX RR (and also the obscure AFSDB and RT RRs)
	elif state == "rr_mx" or state == "rr_mx_paren":
		(state,buffer) = rr_mx(a,o,state,buffer)
	elif state == "rr_mx_2_pre" or state == "rr_mx_2_pre_paren":
		(state,buffer) = rr_mx_2_pre(a,o,state,buffer)
	elif state == "rr_mx_2" or state == "rr_mx_2_paren":
		(state,buffer) = rr_mx_2(a,o,state,buffer)
	elif state == "rr_mx_2_dot" or state == "rr_mx_2_dot_paren":
		(state,buffer) = rr_mx_2_dot(a,o,state,buffer)
	# We have a rr_mx_pre handler because the SRV record
        # uses the MX handler for the last two fields
	elif state == "rr_mx_pre" or state == "rr_mx_pre_paren":
		(state,buffer) = rr_mx(a,o,state,buffer)

	# The SRV RR
	elif state == "rr_srv" or state == "rr_srv_paren":
		(state,buffer) = rr_srv(a,o,state,buffer)
	elif state == "rr_srv_2" or state == "rr_srv_2_paren":
		(state,buffer) = rr_srv_2(a,o,state,buffer)
	elif state == "rr_srv_2_pre" or state == "rr_srv_2_pre_paren":
		(state,buffer) = rr_srv_2_pre(a,o,state,buffer)

	# The AAAA RR
	elif state == "rr_aaaa" or state == "rr_aaaa_paren":
		(state,buffer) = rr_aaaa(a,o,state,buffer)

	# The TXT RR
	elif state == "rr_txt" or state == "rr_txt_paren":
		(state,buffer) = rr_txt(a,o,state,buffer)
	elif state == "rr_txt_2" or state == "rr_txt_2_paren":
		(state,buffer) = rr_txt_2(a,o,state,buffer)
	elif state == "rr_txt_3" or state == "rr_txt_3_paren":
		(state,buffer) = rr_txt_3(a,o,state,buffer)
	elif state == "rr_txt_4" or state == "rr_txt_4_paren":
		(state,buffer) = rr_txt_4(a,o,state,buffer)
	elif state == "rr_txt_backslash" or state == "rr_txt_backslash_paren":
		(state,buffer) = rr_txt_backslash(a,o,state,buffer)
	elif state == "rr_txt_numeric" or state == "rr_txt_numeric_paren":
		(state,buffer) = rr_txt_numeric(a,o,state,buffer)

	# Generic handler for RR with 2 dlabels (MINFO, etc)
	elif state == "rr_2dlabels" or state == "rr_2dlabels_paren":
		(state,buffer) = rr_2dlabels(a,o,state,buffer)
	elif state == "rr_2dlabels_dot" or state == "rr_2dlabels_dot_paren":
		(state,buffer) = rr_2dlabels_dot(a,o,state,buffer)

        # Obscure RRs that take a variable number of arguments
	elif state == "rr_variargs":
		(state,buffer) = rr_variargs(a,o,state,buffer)

        # Before or after the RR
	if state == "postrr" or state == "postrr_paren":
		(state,buffer) = postrr(a,o,state,buffer)
	elif state == "pre_rr":
		(state,buffer) = pre_rr(a,o,state,buffer)

	return (state, buffer)

# Process a given file; this allows this program to process multiple
# BIND zone files at the same time
def process_file(filename):
	if os.access(filename,os.R_OK) != 1:
		print("Can not read " + filename)
		return ERROR
	
	outf = filename + ".csv2"

	if os.path.isfile(outf) == 1:
		print("Warning: " + outf + " already exists, overwriting")

	if os.path.isdir(filename) == 1:
		print("Error: " + outf + " is a directory, skipping")
		return ERROR

	i = open(filename,"rb")
	o = open(outf,"w")
	oz = buf()

	state = "init_state"
	buffer = ""

	x = 0
	linenum = 1
	while x < 100000:
		a = i.read(1).decode('utf-8')
		if a == "":
			break
		if a == ";":
			a = process_comment(i,oz)
		if a == "\n":
			linenum += 1
		(state, buffer) = process_char(a,oz,state,buffer)
		if state == "error" or state == "error_paren":
			print("Error found, no longer processing this file")
			print("Error is on line " + str(linenum) +
			      " of file " + filename)
			return ERROR
		x += 1


	o.write(
"""# This MaraDNS CSV2 zone file was converted from a BIND zone file by
# the bind2csv2.py tool

""")
	oz.flush_rr() # Make sure to flush out the last RR we read
	o.write(oz.read())

	print(outf + " written")


# MAIN

if len(sys.argv) < 3 or sys.argv[1] != "-c":
	print("Usage: bind2csv2.py -c {file list}")
	print("Where {file list} is a list of files you want to make " +
              "csv2 zone files of.")
	sys.exit()

list = sys.argv[2:]
for item in list:
	print("Processing zone file " + item)
	process_file(item)

