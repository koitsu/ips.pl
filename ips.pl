#!/usr/bin/perl

# ips.pl
# version 0.02
#
# This is a quick hack to apply IPS patches. It is distributed under
# the terms of the GNU General Public License.

use strict;
use warnings;
use Fcntl qw(:seek);
use Getopt::Long;

use vars qw($create $debug);

sub usage {
  print <<"EOF";
Usage: $0 DATAFILE IPSFILE
Usage: $0 --create=OUTFILE ORIGINAL MODIFIED

First usage syntax: applies IPS patch IPSFILE to DATAFILE (DATAFILE
is modified).

Second usage syntax: create IPS patch file named OUTFILE, consisting
of the differences between files ORIGINAL and MODIFIED.  The alternate
short flag called -c is available as well.

There is also a --debug (-d) flag available for some debug output
which is only helpful if you understand the internals of the software.

Examples:

  $0 myfile.nes mypatch.ips
  $0 --create=result.ips original.nes modified.nes
  $0 -c result.ips original.nes modified.nes

Original author of this script is unknown.  Original source:
http://www.zophar.net/utilities/patchutil/ips-pl.html

Modified by Jeremy Chadwick <jdc\@koitsu.org> to fix bugs, try to
clean up some of the code, and add IPS patch creation support
(non-RLE).

IPS patch creation code based on ips.py from Frederic Beaudet:
https://github.com/fbeaudet/ips.py

IPS file format: http://zerosoft.zophar.net/ips.php
EOF
  exit(1);
}

sub dprint {
  my $s = shift;
  chomp $s;
  print "==> DEBUG: $s\n" if $debug;
}


#
# MAIN
#
GetOptions(
  "debug|d"    => \$debug,
  "create|c=s" => \$create,
  "help|h|?"   => \&usage
) or usage();

# IPS patch creation mode (non-RLE)
#
if (defined $create) {
  my ($file_orig, $size_orig, $original);
  my ($file_mod, $size_mod, $modified);
  my @record;
  my $recording = 0;

  $file_orig = shift or usage();
  $file_mod  = shift or usage();

  $size_orig = -s $file_orig or die "Can't open $file_orig";
  $size_mod  = -s $file_mod  or die "Can't open $file_mod";

  # XXX: Add limitation check for 16MByte files.  IPS file format
  # has a limitation of a 24-bit offset (2^24 = 16777216).

  open ORIG, "<", $file_orig or die "Can't open $file_orig";
  open MOD, "<", $file_mod   or die "Can't open $file_mod";
  open OUT, ">", $create     or die "Can't write to $create";

  binmode ORIG;
  binmode MOD;
  binmode OUT;

  # XXX: Highly inefficient (reading entire file contents into
  # XXX: memory), but makes our job easier.
  #
  read ORIG, $original, $size_orig;
  read MOD, $modified, $size_mod;

  close ORIG;
  close MOD;

  dprint "    start = PATCH";

  print OUT "PATCH";

  for (my $a = 0; $a < $size_mod; $a++) {
    if ($recording != 1) {
      if (($size_orig <= $a) or (substr($modified, $a, 1) ne substr($original, $a, 1))) {
        @record = ();

        $recording = 1;

        # If the offset happens to equal "EOF", which happens to be the same
        # the string used to mark EOF in the patch itself (great file format!)
        # then return 0x454f45 instead.
        if ($a == 0x454f46) {
          push @record, substr($modified, ($a-1), 1);
        }

        push @record, substr($modified, $a, 1);

        dprint sprintf("offset[0] = %02x", $a >> (16 - (0 * 8)) & 0xff);
        dprint sprintf("offset[1] = %02x", $a >> (16 - (1 * 8)) & 0xff);
        dprint sprintf("offset[2] = %02x", $a >> (16 - (2 * 8)) & 0xff);

        print OUT pack("C3", $a >> (16 - (0 * 8)) & 0xff,
                             $a >> (16 - (1 * 8)) & 0xff,
                             $a >> (16 - (2 * 8)) & 0xff);

        # If we're at the last address, close the record
        if ($a == ($size_mod-1)) {
          $recording = 0;

          dprint "    final = 00 01";

          print OUT "\x00\x01";

          foreach (@record) {
            dprint(sprintf "   record = %02x", ord $_);

            print OUT pack("C", ord $_);
          }
        }
      }
    }
    else {
      if (($size_orig <= $a) or (substr($modified, $a, 1) ne substr($original, $a, 1))) {
        push @record, substr($modified, $a, 1);

        if ($a == ($size_mod-1)) {
          $recording = 0;

          dprint(sprintf "  size[0] = %02x", scalar @record >> (8 - (0 * 8)) & 0xff);
          dprint(sprintf "  size[1] = %02x", scalar @record >> (8 - (1 * 8)) & 0xff);

          print OUT pack("C2", scalar @record >> (8 - (0 * 8)) & 0xff,
                               scalar @record >> (8 - (1 * 8)) & 0xff);

          foreach (@record) {
            dprint(sprintf "   record = %02x", ord $_);

            print OUT pack("C", ord $_);
          }
          dprint "---";
        }
      }
      else {
        $recording = 0;

        dprint sprintf("  size[0] = %02x", scalar @record >> (8 - (0 * 8)) & 0xff);
        dprint sprintf("  size[1] = %02x", scalar @record >> (8 - (1 * 8)) & 0xff);

        print OUT pack("C2", scalar @record >> (8 - (0 * 8)) & 0xff,
                             scalar @record >> (8 - (1 * 8)) & 0xff);

        foreach (@record) {
          dprint sprintf("   record = %02x", ord $_);

          print OUT pack("C", ord $_);
        }
        dprint "---";
      }
    }
  }

  dprint "      end = EOF";

  print OUT "EOF";
  close OUT;
}

# IPS patching mode
else {
  my ($datafile, $ipsfile, $data, $address, $length, $byte);

  $datafile = shift or usage();
  $ipsfile = shift or usage();

  open PAT, $ipsfile or die "Can't open $ipsfile";
  open DAT, "+<", $datafile or die "Can't open $datafile";

  binmode PAT;
  binmode DAT;

  read PAT, $data, 5;
  die "Bad magic bytes in $ipsfile" if $data ne "PATCH";

  while(1) {
    read PAT, $data, 3 or die "Read error";
    last if ($data eq "EOF");

    # This is ugly, but unpack doesn't have anything that's
    # very helpful for THREE-byte numbers.
    #
    $address = ord(substr($data,0,1))*256*256 +
               ord(substr($data,1,1))*256 +
               ord(substr($data,2,1));

    seek DAT, $address, SEEK_SET or die "Failed seek";

    read PAT, $data, 2 or die "Read error";
    $length = ord(substr($data,0,1))*256 +
              ord(substr($data,1,1));

    if ($length) {
      read(PAT, $data, $length) == $length or die "Read error";
      print DAT $data;
    }
    else {
      # RLE mode
      read PAT, $data, 2 or die "Read error";
      $length = ord(substr($data,0,1))*256 + ord(substr($data,1,1));
      read PAT, $byte, 1 or die "Read error";
      print DAT ($byte)x$length;
    }
  }

  close DAT;
  close PAT;
}
