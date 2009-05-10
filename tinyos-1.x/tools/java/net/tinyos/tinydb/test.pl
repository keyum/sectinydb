#!/usr/bin/perl

$interactive = 0;
$runIdx = -1;
$list = 0;
$usage = "test [-i][-l][-n]\n\t-i: Run in interactive mode (prompt for the query to run)\n\t-l: List the queries available and exit\n\t-n: Run query n\n";

for ($arg = 0; $arg <= $#ARGV; $arg++) {
    if ($ARGV[$arg] eq '-n') {
	$arg++;
	$runIdx = $ARGV[$arg];
	$runIdx --;
	if ($runIdx < 0) {
	    print ("Invalid query number : ".( $runIdx + 1));
	    exit 1;
	}
    }
    elsif ($ARGV[$arg] eq '-i') {
	$interactive = 1;
    }
    elsif ($ARGV[$arg] eq '-l') {
	$list = 1;
    }
    else {
	print ("Unknown argument : ARGV[$arg] \n $usage");
	exit 1;
    }
    
}

chdir("../../..");
open($fh, "net/tinyos/tinydb/testqueries");
$i = 0;
    

while (<$fh>) {
    $repeat = 0;
    $queries[$i][0] = $_;

    print $_[0];

   if (substr($_,0,1) eq "#") {
       next;
    }
    

    if ($list) {
	print ++$i.") ".$_;
    }
    elsif ($interactive) {
	#not supported yet
    } else {
	if ($runIdx == -1 ||  $i == $runIdx) {
	    do {
		print "Running $_ \n";
		$repeat = 0;
		$running = 1;
		system("java net.tinyos.tinydb.TinyDBMain -run \"$_\"");
		#while ($running) {
		#}
		#parent
		print ("Retry?");
		$c = getc();
		getc();
		if ($c eq "y") {
		    $repeat = 1;
		} else {
		    print ("Success?");
		    $c = getc();
		    getc();
		    if ($c eq "y") {
			$queries[$i++][1] = 1;
		    } else {
			$queries[$i++][1] = 0;
		    }
		}
	    } while ($repeat == 1);
	} else {
	    $queries[$i++][1] = 1;
	}
    }
}

sub catch_sig_int {
    $running = 0;
}

if (!$interactive && !$list) {
print "Failed queries:\n";
for ($j = 0; $j < $i ; $j++) {
    if ($queries[$j][1] == 0) {
	print ($j + 1).": ".$queries[$j][0]."\n";
    }
}
}
