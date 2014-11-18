#!/usr/bin/perl

# Perl script that can perform a 'du' on a ReiserFS filesystem more
# accurately than the built-in du Linux has

# This program is released to the public domain

sub go {
    my($dir) = @_;
    my($total,$file,@files) = (0,0,());
    opendir(DIR,$dir) || return;
    @files = readdir(DIR);
    foreach $file (@files) {
        next if($file eq "." || $file eq "..");
        ($dev,$ino,$mode,$nlink,$uid,$gid,$rdev,$size,
	 $atime,$mtime,$ctime,$blksize,$blocks) = stat($dir . "/" . $file);
        $total += $size;
	print $dir . "/" . $file . "\t" . $size . "\n";
	if(-d $dir . "/" . $file) {
	    $total += go($dir . "/" . $file);
	    }
        }
    return $total;
    }

$t = go(".");
print "." . "\t" . $t . "\n";

