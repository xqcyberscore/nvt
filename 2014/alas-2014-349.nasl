# OpenVAS Vulnerability Test 
# Description: Amazon Linux security check 
# $Id: alas-2014-349.nasl 6637 2017-07-10 09:58:13Z teissa $
 
# Authors: 
# Eero Volotinen <eero.volotinen@iki.fi> 
#
# Copyright:
# Copyright (c) 2015 Eero Volotinen, http://ping-viini.org 
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#
if(description)
 {
script_oid("1.3.6.1.4.1.25623.1.0.120468");
script_version("$Revision: 6637 $");
script_tag(name:"creation_date", value:"2015-09-08 13:27:05 +0200 (Tue, 08 Sep 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-10 11:58:13 +0200 (Mon, 10 Jul 2017) $");
script_name("Amazon Linux Local Check: ALAS-2014-349");
script_tag(name: "insight", value: "It was found that OpenSSL clients and servers could be forced, via a specially crafted handshake packet, to use weak keying material for communication. A man-in-the-middle attacker could use this flaw to decrypt and modify traffic between a client and a server. (CVE-2014-0224 )Note: In order to exploit this flaw, both the server and the client must be using a vulnerable version of OpenSSL; the server must be using OpenSSL version 1.0.1 and above, and the client must be using any version of OpenSSL.A buffer overflow flaw was found in the way OpenSSL handled invalid DTLS packet fragments. A remote attacker could possibly use this flaw to execute arbitrary code on a DTLS client or server. (CVE-2014-0195 )Multiple flaws were found in the way OpenSSL handled read and write buffers when the SSL_MODE_RELEASE_BUFFERS mode was enabled. A TLS/SSL client or server using OpenSSL could crash or unexpectedly drop connections when processing certain SSL traffic. (CVE-2010-5298 , CVE-2014-0198 )A denial of service flaw was found in the way OpenSSL handled certain DTLS ServerHello requests. A specially crafted DTLS handshake packet could cause a DTLS client using OpenSSL to crash. (CVE-2014-0221 )A NULL pointer dereference flaw was found in the way OpenSSL performed anonymous Elliptic Curve Diffie Hellman (ECDH) key exchange. A specially crafted handshake packet could cause a TLS/SSL client that has the anonymous ECDH cipher suite enabled to crash. (CVE-2014-3470 )An integer underflow flaw, leading to a heap-based buffer overflow, was found in the way OpenSSL decoded certain base64 strings. A remote attacker could provide a specially crafted base64 string via certain PEM processing routines that, when parsed by the OpenSSL library, would cause the OpenSSL server to crash. (CVE-2015-0292 )"); 
script_tag(name : "solution", value : "Run yum update openssl to update your system.");
script_tag(name : "solution_type", value : "VendorFix");
script_xref(name : "URL" , value : "https://alas.aws.amazon.com/ALAS-2014-349.html");
script_cve_id("CVE-2015-0292", "CVE-2014-0221", "CVE-2014-0198", "CVE-2014-0224", "CVE-2010-5298", "CVE-2014-3470", "CVE-2014-0195");
script_tag(name:"cvss_base", value:"7.5");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_tag(name:"qod_type", value:"package");
script_dependencies("gather-package-list.nasl");
script_mandatory_keys("ssh/login/amazon_linux", "ssh/login/release");
script_category(ACT_GATHER_INFO);
script_tag(name:"summary", value:"Amazon Linux Local Security Checks");
script_copyright("Eero Volotinen");
script_family("Amazon Linux Local Security Checks");
exit(0);
}
include("revisions-lib.inc");
include("pkg-lib-rpm.inc");
release = get_kb_item("ssh/login/release");
res = "";
if(release == NULL)
{
 exit(0);
}
if(release == "AMAZON")
{
if ((res = isrpmvuln(pkg:"openssl-devel", rpm:"openssl-devel~1.0.1h~1.72.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"openssl", rpm:"openssl~1.0.1h~1.72.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"openssl-debuginfo", rpm:"openssl-debuginfo~1.0.1h~1.72.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"openssl-perl", rpm:"openssl-perl~1.0.1h~1.72.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"openssl-static", rpm:"openssl-static~1.0.1h~1.72.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);
}
