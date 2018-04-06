#
#VID 78cc8a46-3e56-11e1-89b4-001ec9578670
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID 78cc8a46-3e56-11e1-89b4-001ec9578670
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com
# Text descriptions are largely excerpted from the referenced
# advisories, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

include("revisions-lib.inc");
tag_insight = "The following package is affected: openssl

CVE-2011-4108
The DTLS implementation in OpenSSL before 0.9.8s and 1.x before 1.0.0f
performs a MAC check only if certain padding is valid, which makes it
easier for remote attackers to recover plaintext via a padding oracle
attack.

CVE-2011-4109
Double free vulnerability in OpenSSL 0.9.8 before 0.9.8s, when
X509_V_FLAG_POLICY_CHECK is enabled, allows remote attackers to have
an unspecified impact by triggering failure of a policy check.

CVE-2011-4576
The SSL 3.0 implementation in OpenSSL before 0.9.8s and 1.x before
1.0.0f does not properly initialize data structures for block cipher
padding, which might allow remote attackers to obtain sensitive
information by decrypting the padding data sent by an SSL peer.

CVE-2011-4577
OpenSSL before 0.9.8s and 1.x before 1.0.0f, when RFC 3779 support is
enabled, allows remote attackers to cause a denial of service
(assertion failure) via an X.509 certificate containing
certificate-extension data associated with (1) IP address blocks or
(2) Autonomous System (AS) identifiers.

CVE-2011-4619
The Server Gated Cryptography (SGC) implementation in OpenSSL before
0.9.8s and 1.x before 1.0.0f does not properly handle handshake
restarts, which allows remote attackers to cause a denial of service
via unspecified vectors.

CVE-2012-0027
The GOST ENGINE in OpenSSL before 1.0.0f does not properly handle
invalid parameters for the GOST block cipher, which allows remote
attackers to cause a denial of service (daemon crash) via crafted data
from a TLS client.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://openssl.org/news/secadv_20120104.txt
http://www.vuxml.org/freebsd/78cc8a46-3e56-11e1-89b4-001ec9578670.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.70756");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_cve_id("CVE-2011-4108", "CVE-2011-4109", "CVE-2011-4576", "CVE-2011-4577", "CVE-2011-4619", "CVE-2012-0027");
 script_version("$Revision: 9352 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2012-02-12 07:27:20 -0500 (Sun, 12 Feb 2012)");
 script_name("FreeBSD Ports: openssl");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com");
 script_family("FreeBSD Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/freebsdrel", "login/SSH/success");
 script_tag(name : "insight" , value : tag_insight);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name:"qod_type", value:"package");
 script_tag(name:"solution_type", value:"VendorFix");
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-bsd.inc");

txt = "";
vuln = 0;
txt = "";
bver = portver(pkg:"openssl");
if(!isnull(bver) && revcomp(a:bver, b:"1.0.0_8")<0) {
    txt += 'Package openssl version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
