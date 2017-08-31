# OpenVAS Vulnerability Test 
# Description: Amazon Linux security check 
# $Id: alas-2012-38.nasl 6578 2017-07-06 13:44:33Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.120204");
script_version("$Revision: 6578 $");
script_tag(name:"creation_date", value:"2015-09-08 13:20:04 +0200 (Tue, 08 Sep 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 15:44:33 +0200 (Thu, 06 Jul 2017) $");
script_name("Amazon Linux Local Check: ALAS-2012-38");
script_tag(name: "insight", value: "It was discovered that the Datagram Transport Layer Security (DTLS) protocol implementation in OpenSSL leaked timing information when performing certain operations. A remote attacker could possibly use this flaw to retrieve plain text from the encrypted packets by using a DTLS server as a padding oracle. (CVE-2011-4108 )An information leak flaw was found in the SSL 3.0 protocol implementation in OpenSSL. Incorrect initialization of SSL record padding bytes could cause an SSL client or server to send a limited amount of possibly sensitive data to its SSL peer via the encrypted connection. (CVE-2011-4576 )A denial of service flaw was found in the RFC 3779 implementation in OpenSSL. A remote attacker could use this flaw to make an application using OpenSSL exit unexpectedly by providing a specially-crafted X.509 certificate that has malformed RFC 3779 extension data. (CVE-2011-4577 )It was discovered that OpenSSL did not limit the number of TLS/SSL handshake restarts required to support Server Gated Cryptography. A remote attacker could use this flaw to make a TLS/SSL server using OpenSSL consume an excessive amount of CPU by continuously restarting the handshake. (CVE-2011-4619 )"); 
script_tag(name : "solution", value : "Run yum update openssl to update your system.");
script_tag(name : "solution_type", value : "VendorFix");
script_xref(name : "URL" , value : "https://alas.aws.amazon.com/ALAS-2012-38.html");
script_cve_id("CVE-2011-4577", "CVE-2011-4576", "CVE-2011-4108", "CVE-2011-4619");
script_tag(name:"cvss_base", value:"5.0");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
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
if ((res = isrpmvuln(pkg:"openssl", rpm:"openssl~1.0.0g~1.26.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"openssl-perl", rpm:"openssl-perl~1.0.0g~1.26.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"openssl-devel", rpm:"openssl-devel~1.0.0g~1.26.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"openssl-debuginfo", rpm:"openssl-debuginfo~1.0.0g~1.26.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"openssl-static", rpm:"openssl-static~1.0.0g~1.26.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);
}
