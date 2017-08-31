# OpenVAS Vulnerability Test 
# Description: Amazon Linux security check 
# $Id: alas-2016-682.nasl 6574 2017-07-06 13:41:26Z cfischer $
 
# Authors: 
# Eero Volotinen <eero.volotinen@iki.fi> 
#
# OpenVAS and security consultance available from openvas@solinor.com
# see https://solinor.fi/openvas-en/ for more information
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
script_oid("1.3.6.1.4.1.25623.1.0.120672");
script_version("$Revision: 6574 $");
script_tag(name:"creation_date", value:"2016-05-09 14:11:48 +0300 (Mon, 09 May 2016)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 15:41:26 +0200 (Thu, 06 Jul 2017) $");
script_name("Amazon Linux Local Check: alas-2016-682");
script_tag(name: "insight", value: "A denial of service flaw was found in the way OpenSSL handled SSLv2 handshake messages. A remote attacker could use this flaw to cause a TLS/SSL server using OpenSSL to exit on a failed assertion if it had both the SSLv2 protocol and EXPORT-grade cipher suites enabled. (CVE-2015-0293 )It was discovered that the SSLv2 servers using OpenSSL accepted SSLv2 connection handshakes that indicated non-zero clear key length for non-export cipher suites. An attacker could use this flaw to decrypt recorded SSLv2 sessions with the server by using it as a decryption oracle. (CVE-2016-0703 )It was discovered that the SSLv2 protocol implementation in OpenSSL did not properly implement the Bleichenbacher protection for export cipher suites. An attacker could use a SSLv2 server using OpenSSL as a Bleichenbacher oracle. (CVE-2016-0704 )A padding oracle flaw was found in the Secure Sockets Layer version 2.0 (SSLv2) protocol. An attacker can potentially use this flaw to decrypt RSA-encrypted cipher text from a connection using a newer SSL/TLS protocol version, allowing them to decrypt such connections. This cross-protocol attack is publicly referred to as DROWN. (CVE-2016-0800 )A flaw was found in the way malicious SSLv2 clients could negotiate SSLv2 ciphers that have been disabled on the server. This could result in weak SSLv2 ciphers being used for SSLv2 connections, making them vulnerable to man-in-the-middle attacks. (CVE-2015-3197 )"); 
script_tag(name : "solution", value : "Run yum update openssl098e to update your system.");
script_tag(name : "solution_type", value : "VendorFix");
script_xref(name : "URL" , value : "https://alas.aws.amazon.com/ALAS-2016-682.html");
script_cve_id("CVE-2015-0293","CVE-2016-0703","CVE-2016-0704","CVE-2016-0800","CVE-2015-3197");
script_tag(name:"cvss_base", value:"5.0");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
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
if ((res = isrpmvuln(pkg:"openssl098e", rpm:"openssl098e~0.9.8e~29.19.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"openssl098e-debuginfo", rpm:"openssl098e-debuginfo~0.9.8e~29.19.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);
}
