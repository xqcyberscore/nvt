# OpenVAS Vulnerability Test 
# Description: Mageia Linux security check 
# $Id: mgasa-2015-0268.nasl 6563 2017-07-06 12:23:47Z cfischer $
 
# Authors: 
# Eero Volotinen <eero.volotinen@solinor.com> 
#
# Copyright:
# Copyright (c) 2015 Eero Volotinen, http://www.solinor.com
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
script_oid("1.3.6.1.4.1.25623.1.0.130109");
script_version("$Revision: 6563 $");
script_tag(name:"creation_date", value:"2015-10-15 10:42:49 +0300 (Thu, 15 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 14:23:47 +0200 (Thu, 06 Jul 2017) $");
script_name("Mageia Linux Local Check: mgasa-2015-0268");
script_tag(name: "insight", value: "Several flaws were found in the processing of malformed web content. A web page containing malicious content could cause Firefox to crash or, potentially, execute arbitrary code with the privileges of the user running Firefox (CVE-2015-2722, CVE-2015-2724, CVE-2015-2728, CVE-2015-2733, CVE-2015-2734, CVE-2015-2735, CVE-2015-2736, CVE-2015-2737, CVE-2015-2738, CVE-2015-2739, CVE-2015-2740). A flaw was discovered in Mozilla's PDF.js PDF file viewer. When combined with another vulnerability, it could allow execution of arbitrary code with the privileges of the user running Firefox (CVE-2015-2743). A vulnerability in the TLS protocol allows a man-in-the-middle attacker to downgrade vulnerable TLS connections using ephemeral Diffie-Hellman key exchange to 512-bit export-grade cryptography. This vulnerability is known as Logjam (CVE-2015-4000). Security researcher Karthikeyan Bhargavan reported an issue in Network Security Services (NSS) where the client allows for a ECDHE_ECDSA exchange where the server does not send its ServerKeyExchange message instead of aborting the handshake. Instead, the NSS client will take the EC key from the ECDSA certificate. This violates the TLS protocol and also has some security implications for forward secrecy. In this situation, the browser thinks it is engaged in an ECDHE exchange, but has been silently downgraded to a non-forward secret mixed-ECDH exchange instead. As a result, if False Start is enabled, the browser will start sending data encrypted under these non-forward-secret connection keys (CVE-2015-2721). Mozilla community member Watson Ladd reported that the implementation of Elliptical Curve Cryptography (ECC) multiplication for Elliptic Curve Digital Signature Algorithm (ECDSA) signature validation in Network Security Services (NSS) did not handle exceptional cases correctly. This could potentially allow for signature forgery (CVE-2015-2730). The nss package has been updated to version 3.19.2, which fixes issues related to the minimum key sizes of finite field algorithms, including CVE-2015-4000. It also fixes CVE-2015-2721 and CVE-2015-2730. The Mageia 4 sqlite3 package has also been updated to version 3.8.10.2, fixing an index corruption issue. Mageia 5 already shipped with version 3.8.10.2."); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_xref(name : "URL" , value : "https://advisories.mageia.org/MGASA-2015-0268.html");
script_cve_id("CVE-2015-2721","CVE-2015-2722","CVE-2015-2724","CVE-2015-2728","CVE-2015-2730","CVE-2015-2733","CVE-2015-2734","CVE-2015-2735","CVE-2015-2736","CVE-2015-2737","CVE-2015-2738","CVE-2015-2739","CVE-2015-2740","CVE-2015-2743","CVE-2015-4000");
script_tag(name:"cvss_base", value:"10.0");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_tag(name:"qod_type", value:"package");
script_dependencies("gather-package-list.nasl");
script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release");
script_category(ACT_GATHER_INFO);
script_tag(name : "summary", value : "Mageia Linux Local Security Checks mgasa-2015-0268");
script_copyright("Eero Volotinen");
script_family("Mageia Linux Local Security Checks");
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
if(release == "MAGEIA5")
{
if ((res = isrpmvuln(pkg:"nss", rpm:"nss~3.19.2~1.mga5", rls:"MAGEIA5")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"firefox", rpm:"firefox~38.1.0~1.mga5", rls:"MAGEIA5")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"firefox-l10n", rpm:"firefox-l10n~38.1.0~1.mga5", rls:"MAGEIA5")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);
}
