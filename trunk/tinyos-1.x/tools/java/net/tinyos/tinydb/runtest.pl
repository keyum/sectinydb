#!/usr/bin/perl

$usage = "runtest filename\nfilename: file containing TinyDB SQL statements.\n";

print("number of args: $#ARGV\n");
if ($#ARGV != 0)
{
	print ($usage);
	exit 1;
}
$filename = $ARGV[0];
print("filename = $filename\n");

open($fh, $filename);
chdir("../../..");
while (<$fh>) {
	if (substr($_,0,1) eq "#") {
       next;
    }
    
    print "running query: $_\n";
	system("java net.tinyos.tinydb.TinyDBMain -run \"$_\"");
}

sub catch_sig_int
{
	exit(1);
}
