ISACware - IMail SMTP Access Control list maker
=======================

[![Project Status: Concept – Minimal or no implementation has been done yet, or the repository is only intended to be a limited example, demo, or proof-of-concept.](https://www.repostatus.org/badges/latest/concept.svg)](https://www.repostatus.org/#concept)

This script takes files from http://www.okean.com/ in CIDR format
or from http://blackholes.us/ in rbldnsd format and converts them
into the binary format that IPSwitch IMail 8 uses for storing
SMTP Access Control lists.

IPSwitch IMail 8 uses a file named smtpd32.acc to store the
access control lists. This script creates that file.

Download the files you want to form into the access control
list to the same directory as isac.php. Then you can run
isac.php through your local web server.

This script includes a version of the PEAR script Net_IPv4,
which is required for the operation of isac.php. If you have
PEAR's Net_IPv4 installed properly, you shouldn't need to
keep the included version.

When using PHP5, you may ignore any Strict Standards notices
output by Net_IPv4 during the parsing of the input.

As of the date of this writing, blackholes.us is down. In case
it doesn't ever come back, example files are included from the
site for nigeria.txt and malaysia.txt.

The included smtpd32.acc file is an example with the
sinokoreacidr.txt and countries.rbl information.


How the Script Parses Input
----------------------

Regardless of the file input, all parsed addresses are expected
to be a Classless Inter-Domain Routing address (e.g. 192.168.1.0/24).

Files listed in the Okean configuration variable are read by
looking for netblocks in CIDR format (xx.xx.xx.xx/xx) in the
character space of each line until it hits whitespace like a
space or tab. Lines starting with a pound # are considered
comments and ignored.

Files in Blackholes.us format look for CIDR netblocks
(xx.xx.xx.xx/xx) after you select which countries you want to
include through the HTML form. The HTML form can be overridden
by setting a custom array of two-letter country codes in
$_POST['blackholes_selected_countries']
