# OpenVAS Vulnerability Test 
# Description: Amazon Linux security check 
# $Id: alas-2015-498.nasl 6575 2017-07-06 13:42:08Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.120164");
script_version("$Revision: 6575 $");
script_tag(name:"creation_date", value:"2015-09-08 13:18:57 +0200 (Tue, 08 Sep 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 15:42:08 +0200 (Thu, 06 Jul 2017) $");
script_name("Amazon Linux Local Check: ALAS-2015-498");
script_tag(name: "insight", value: "A use-after-free flaw was found in the way OpenSSL importrf certain Elliptic Curve private keys. An attacker could use this flaw to crash OpenSSL, if a specially-crafted certificate was imported. (CVE-2015-0209 )A denial of service flaw was found in the way OpenSSL handled certain SSLv2 messages. A malicious client could send a specially crafted SSLv2 CLIENT-MASTER-KEY message that would cause an OpenSSL server that both supports SSLv2 and enables EXPORT-grade cipher suites to crash.  (CVE-2015-0293 )An out-of-bounds write flaw was found in the way OpenSSL reused certain ASN.1 structures. A remote attacker could use a specially crafted ASN.1 structure that, when parsed by an application, would cause that application to crash. (CVE-2015-0287 )A flaw was found in the the ASN (Abstract Syntax Notation) parsing code of OpenSSL. An attacker could present a specially crafted certificate, which when verified by an OpenSSL client or server could cause it to crash. (CVE-2015-0286 )A null-pointer dereference was found in the way OpenSSL handled certain PKCS#7 blobs. An attacker could cause OpenSSL to crash, when applications verify, decrypt or parsed these ASN.1 encoded PKCS#7 blobs. OpenSSL clients and servers are not affected. (CVE-2015-0289 )A NULL pointer dereference flaw was found in OpenSSL's x509 certificate handling implementation. A remote attacker could use this flaw to crash an OpenSSL server using an invalid certificate key. (CVE-2015-0288 )"); 
script_tag(name : "solution", value : "Run yum update openssl to update your system.");
script_tag(name : "solution_type", value : "VendorFix");
script_xref(name : "URL" , value : "https://alas.aws.amazon.com/ALAS-2015-498.html");
script_cve_id("CVE-2015-0209", "CVE-2015-0293", "CVE-2015-0287", "CVE-2015-0286", "CVE-2015-0289", "CVE-2015-0288");
script_tag(name:"cvss_base", value:"6.8");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
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
if ((res = isrpmvuln(pkg:"openssl-debuginfo", rpm:"openssl-debuginfo~1.0.1k~1.84.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"openssl-perl", rpm:"openssl-perl~1.0.1k~1.84.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"openssl", rpm:"openssl~1.0.1k~1.84.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"openssl-devel", rpm:"openssl-devel~1.0.1k~1.84.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"openssl-static", rpm:"openssl-static~1.0.1k~1.84.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);
}
