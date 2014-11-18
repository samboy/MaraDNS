#!/bin/sh

eval 'exec perl -x $0 ${1+"$@"}'
	if 0;

# This hack makes a shell script which calls Perl also a Perl script.  
# We do it this way so this script will run on a system where the user 
# has Perl, even if Perl is in /usr/local/bin instead of /usr/bin

#!/usr/bin/perl
# This is a tool for converting CSV1 zone files in to a CSV2 compatible format

# Cleanup: Subroutine that removes potentially dangerous stuff from a hostname
sub cleanup {
	my($in) = @_;
	# Security: Get rid of all ASCII except [0-9A-Za-z\.\@\%\_\-]
	$in =~ s/[^0-9A-Za-z\.\@\%\x80-\xff\-\_]//g;
	# Get rid of all % except trailing %
	if($in =~ /\%$/) {
		$in =~ s/\%//g;
		$in = $in . "%";
	} else { $in =~ s/\%//g; }
	return nonmt($in);
}

# non-empty: Subroutine that makes sure a string is not empty
sub nonmt {
	my($in) = @_;
	return nonmt_r($in,"0");
}

sub nonmt_q {
	my($in) = @_;
	return nonmt_r($in,"\'\'");
}

sub nonmt_r {
	my($in,$replace) = @_;
	if($in =~ /^[\s\|]*$/) {
		$in = $replace;
	}
	return $in;
}

while(<>) {
	if(/^#/) {print;next;} # Comments are printed as-is
	if(/^\s*$/) {print;next;} # Ditto with lines with just whitespace
	if(/^(.)(.*)/) {$rrtype = $1; $rest=$2;
		($hostname,$ttl,$rdata) = split(/\|/,$rest,3);

		# Do security cleanup on hostname
		$hostname = cleanup($hostname);
		# Security: Get rid of anything that isn't a number in ttl
		$ttl =~ s/[^0-9]//g;
		$ttl = nonmt($ttl);

		if($rrtype =~ /^A/) {
			# Remove non numeric and dot from rdata
			$rdata =~ s/[^0-9\.]//g;
			$rdata = nonmt($rdata);
			print "$hostname|+$ttl|A|$rdata\n";
		} elsif($rrtype =~ /^N/) {
			$rdata = cleanup($rdata);
			print "$hostname|+$ttl|NS|$rdata\n";
		} elsif($rrtype =~ /^P/) {
			$rdata = cleanup($rdata);
			print "$hostname|+$ttl|PTR|$rdata\n";
		} elsif($rrtype =~ /^C/) {
			$rdata = cleanup($rdata);
			print "$hostname|+$ttl|CNAME|$rdata\n";
		} elsif($rrtype =~ /^@/) {
			# MX records
			($priority,$h) = split(/\|/,$rdata,2);
			$priority =~ s/[^0-9]//g;
			$h = cleanup($h);
			$priority = nonmt($priority);
			print "$hostname|+$ttl|MX|$priority|$h\n";
		} elsif($rrtype =~ /^S/) {
			# SOA records
			($o,$e,$s,$rf,$rt,$ex,$min) = split(/\|/,$rdata,7);
			$o = cleanup($o);
			$e = cleanup($e);
			$s =~ s/[^0-9]//g;
			$s = nonmt($s);
			$rf =~ s/[^0-9]//g;
			$rf = nonmt($rf);
			$rt =~ s/[^0-9]//g;
			$rt = nonmt($rt);
			$ex =~ s/[^0-9]//g;
			$ex = nonmt($ex);
			$min =~ s/[^0-9]//g;
			$min = nonmt($min);
		       print "$hostname|+$ttl|SOA|$o|$e|$s|$rf|$rt|$ex|$min\n";
	        }
                # It's a little tricky converting TXT and RAW records; this
		# hopefully covers all real-world examples.
		elsif($rrtype =~ /^T/ || $rrtype =~ /^U/) {
			if($rrtype =~ /^U/) {
				($rrnum,$rdata) = split(/\|/,$rdata,2);
			}

			# Security: Get rid of backslashes that would cause
			# a syntax error when parsed with the csv1 parser
			$rdata =~ s/\\([^\\\%0-3])/$1/g; 

			$rdata =~ s/\'/\'\\\'\'/g; # make ' -> '\'' (ugh)
			$rdata =~ s/\\\%/%/g;      # make \% just %
			$rdata =~ s/\\\\/\\/g;     # make \\ just \

			# The following line puts octal numbers outside of
			# quotes, since they can not be quoted.
			$rdata =~ s/(\\[0-3][0-7][0-7])/\'$1\'/g; 

			# get rid of ugly (but yes parsable) '' sequences
			# '\001''\002''\003' -> '\001\002\003'
			$rdata =~ 
			  s/(\\[0-3][0-7][0-7])\'\'(\\[0-3][0-7][0-7])/$1$2/g;
			# '\'''\'''\'' -> '\'\'\'' by making ''\' simply \'
			$rdata =~ s/\'\'\\\'/\\\'/g;

			# Put quotes around the string
			$rdata = "\'" . $rdata . "\'";

			# The next two lines get rid of ugly '' at the 
			# beginning and end of the string
			$rdata =~ s/^\'\'//;
			$rdata =~ s/\'\'$//;

			# Make sure the final string is not empty
			$rdata = nonmt_q($rdata);

			if($rrtype =~ /^T/) {
				print "$hostname|+$ttl|TXT|$rdata\n";
			} else {
				print "$hostname|+$ttl|RAW|$rrnum|$rdata\n";
			}
		}
	}
}
