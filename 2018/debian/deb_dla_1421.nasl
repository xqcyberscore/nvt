###############################################################################
# OpenVAS Vulnerability Test
# $Id: deb_dla_1421.nasl 10520 2018-07-17 07:26:39Z cfischer $
#
# Auto-generated from advisory DLA 1421-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH http://greenbone.net
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891421");
  script_version("$Revision: 10520 $");
  script_cve_id("CVE-2015-9096", "CVE-2016-2339", "CVE-2016-7798", "CVE-2017-0898", "CVE-2017-0899",
                "CVE-2017-0900", "CVE-2017-0901", "CVE-2017-0902", "CVE-2017-0903", "CVE-2017-10784",
                "CVE-2017-14033", "CVE-2017-14064", "CVE-2017-17405", "CVE-2017-17742", "CVE-2017-17790",
                "CVE-2018-1000075", "CVE-2018-1000076", "CVE-2018-1000077", "CVE-2018-1000078", "CVE-2018-1000079",
                "CVE-2018-6914", "CVE-2018-8777", "CVE-2018-8778", "CVE-2018-8779", "CVE-2018-8780");
  script_name("Debian LTS Advisory ([SECURITY] [DLA 1421-1] ruby2.1 security update)");
  script_tag(name:"last_modification", value:"$Date: 2018-07-17 09:26:39 +0200 (Tue, 17 Jul 2018) $");
  script_tag(name:"creation_date", value:"2018-07-16 00:00:00 +0200 (Mon, 16 Jul 2018)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2018/07/msg00012.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8\.[0-9]+");
  script_tag(name:"affected", value:"ruby2.1 on Debian Linux");
  script_tag(name:"insight", value:"Ruby is the interpreted scripting language for quick and easy
object-oriented programming. It has many features to process text
files and to do system management tasks (as in perl). It is simple,
straight-forward, and extensible.");
  script_tag(name:"solution", value:"For Debian 8 'Jessie', these problems have been fixed in version
2.1.5-2+deb8u4.

We recommend that you upgrade your ruby2.1 packages.");
  script_tag(name:"summary",  value:"Multiple vulnerabilities were found in the interpreter for the Ruby
language. The Common Vulnerabilities and Exposures project identifies the
following issues:

CVE-2015-9096

SMTP command injection in Net::SMTP via CRLF sequences in a RCPT TO
or MAIL FROM command.

CVE-2016-2339

Exploitable heap overflow in Fiddle::Function.new.

CVE-2016-7798

Incorrect handling of initialization vector in the GCM mode in the
OpenSSL extension.

CVE-2017-0898

Buffer underrun vulnerability in Kernel.sprintf.

CVE-2017-0899

ANSI escape sequence vulnerability in RubyGems.

CVE-2017-0900

DoS vulnerability in the RubyGems query command.

CVE-2017-0901

gem installer allowed a malicious gem to overwrite arbitrary files.

CVE-2017-0902

RubyGems DNS request hijacking vulnerability.

CVE-2017-0903

Max Justicz reported that RubyGems is prone to an unsafe object
deserialization vulnerability. When parsed by an application which
processes gems, a specially crafted YAML formatted gem specification
can lead to remote code execution.

CVE-2017-10784

Yusuke Endoh discovered an escape sequence injection vulnerability in
the Basic authentication of WEBrick. An attacker can take advantage of
this flaw to inject malicious escape sequences to the WEBrick log and
potentially execute control characters on the victim's terminal
emulator when reading logs.

CVE-2017-14033

asac reported a buffer underrun vulnerability in the OpenSSL
extension. A remote attacker could take advantage of this flaw to
cause the Ruby interpreter to crash leading to a denial of service.

CVE-2017-14064

Heap memory disclosure in the JSON library.

CVE-2017-17405

A command injection vulnerability in Net::FTP might allow a
malicious FTP server to execute arbitrary commands.

CVE-2017-17742

Aaron Patterson reported that WEBrick bundled with Ruby was vulnerable
to an HTTP response splitting vulnerability. It was possible for an
attacker to inject fake HTTP responses if a script accepted an
external input and output it without modifications.

CVE-2017-17790

A command injection vulnerability in lib/resolv.rb's lazy_initialze
might allow a command injection attack. However untrusted input to
this function is rather unlikely.

CVE-2018-6914

ooooooo_q discovered a directory traversal vulnerability in the
Dir.mktmpdir method in the tmpdir library. It made it possible for
attackers to create arbitrary directories or files via a .. (dot dot)
in the prefix argument.

CVE-2018-8777

Eric Wong reported an out-of-memory DoS vulnerability related to a
large request in WEBrick bundled with Ruby.

CVE-2018-8778

aerodudrizzt found a buffer under-read vulnerability in the Ruby
String#unpack method. If a big number was passed with the specifier @,
the number was treated as a negative value, and an out-of-buffer read
occurred. Attackers could read data on heaps if an script accepts an
external input as the argument of String#unpack.

CVE-2018-8779

ooooooo_q reported that the UNIXServer.open and UNIXSocket.open
methods of the socket library bundled with Ruby did not check for NUL
bytes in the path argument. The lack of check made the methods
vulnerable to unintentional socket creation and unintentional socket
access.

CVE-2018-8780

ooooooo_q discovered an unintentional directory traversal in
some methods in Dir, by the lack of checking for NUL bytes in their
parameter.

CVE-2018-1000075

A negative size vulnerability in ruby gem package tar header that could
cause an infinite loop.

CVE-2018-1000076

RubyGems package improperly verifies cryptographic signatures. A mis-signed
gem could be installed if the tarball contains multiple gem signatures.

CVE-2018-1000077

An improper input validation vulnerability in RubyGems specification
homepage attribute could allow malicious gem to set an invalid homepage
URL.

CVE-2018-1000078

Cross Site Scripting (XSS) vulnerability in gem server display of homepage
attribute.

CVE-2018-1000079

Path Traversal vulnerability during gem installation.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if ((res = isdpkgvuln(pkg:"libruby2.1", ver:"2.1.5-2+deb8u4", rls_regex:"DEB8\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ruby2.1", ver:"2.1.5-2+deb8u4", rls_regex:"DEB8\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ruby2.1-dev", ver:"2.1.5-2+deb8u4", rls_regex:"DEB8\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ruby2.1-doc", ver:"2.1.5-2+deb8u4", rls_regex:"DEB8\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ruby2.1-tcltk", ver:"2.1.5-2+deb8u4", rls_regex:"DEB8\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}

if (report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}
