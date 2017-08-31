# OpenVAS Vulnerability Test 
# Description: Amazon Linux security check 
# $Id: alas-2015-550.nasl 6575 2017-07-06 13:42:08Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.120033");
script_version("$Revision: 6575 $");
script_tag(name:"creation_date", value:"2015-09-08 13:15:46 +0200 (Tue, 08 Sep 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 15:42:08 +0200 (Thu, 06 Jul 2017) $");
script_name("Amazon Linux Local Check: ALAS-2015-550");
script_tag(name: "insight", value: "LOGJAM: A flaw was found in the way the TLS protocol composes the Diffie-Hellman exchange (for both export and non-export grade cipher suites). An attacker could use this flaw to downgrade a DHE connection to use export-grade key sizes, which could then be broken by sufficient pre-computation. This can lead to a passive man-in-the-middle attack in which the attacker is able to decrypt all traffic. (CVE-2015-4000 )An out-of-bounds read flaw was found in the X509_cmp_time() function of OpenSSL, which is used to test the expiry dates of SSL/TLS certificates. An attacker could possibly use a specially-crafted SSL/TLS certificate or CRL (Certificate Revocation List), which when parsed by an application would cause that application to crash.  (CVE-2015-1789 )A NULL pointer dereference was found in the way OpenSSL handled certain PKCS#7 inputs. An attacker able to make an application using OpenSSL verify, decrypt, or parse a specially crafted PKCS#7 input could cause that application to crash. TLS/SSL clients and servers using OpenSSL were not affected by this flaw.  (CVE-2015-1790 )A race condition was found in the session handling code of OpenSSL. An attacker could cause a multi-threaded SSL/TLS server to crash. (CVE-2015-1791 )A denial of service flaw was found in OpenSSL in the way it verified certain signed messages using CMS (Cryptographic Message Syntax). A remote attacker could cause an application using OpenSSL to use excessive amounts of memory by sending a specially-crafted message for verification.  (CVE-2015-1792 )An invalid-free flaw was found in the way OpenSSL handled certain DTLS handshake messages. A malicious DTLS client or server could send a specially-crafted message to the peer, which could cause the application to crash or potentially cause arbitrary code execution. (CVE-2014-8176 )A regression was found in the ssleay_rand_bytes() function. This could lead a multi-threaded application to crash.  (CVE-2015-3216 )"); 
script_tag(name : "solution", value : "Run yum update openssl to update your system.");
script_tag(name : "solution_type", value : "VendorFix");
script_xref(name : "URL" , value : "https://alas.aws.amazon.com/ALAS-2015-550.html");
script_cve_id("CVE-2015-1789", "CVE-2015-1790", "CVE-2015-1791", "CVE-2015-1792", "CVE-2014-8176", "CVE-2015-3216", "CVE-2015-4000");
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
if ((res = isrpmvuln(pkg:"openssl-devel", rpm:"openssl-devel~1.0.1k~10.86.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"openssl-static", rpm:"openssl-static~1.0.1k~10.86.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"openssl", rpm:"openssl~1.0.1k~10.86.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"openssl-perl", rpm:"openssl-perl~1.0.1k~10.86.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"openssl-debuginfo", rpm:"openssl-debuginfo~1.0.1k~10.86.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);
}
