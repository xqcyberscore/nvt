# OpenVAS Vulnerability Test 
# Description: Amazon Linux security check 
# $Id: alas-2016-695.nasl 6574 2017-07-06 13:41:26Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.120684");
script_version("$Revision: 6574 $");
script_tag(name:"creation_date", value:"2016-05-09 14:12:00 +0300 (Mon, 09 May 2016)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 15:41:26 +0200 (Thu, 06 Jul 2017) $");
script_name("Amazon Linux Local Check: alas-2016-695");
script_tag(name: "insight", value: "A vulnerability was discovered that allows a man-in-the-middle attacker to use a padding oracle attack to decrypt traffic on a connection using an AES CBC cipher with a server supporting AES-NI. (CVE-2016-2107 , Important)It was discovered that the ASN.1 parser can misinterpret a large universal tag as a negative value. If an application deserializes and later reserializes untrusted ASN.1 structures containing an ANY field, an attacker may be able to trigger an out-of-bounds write, which can cause potentially exploitable memory corruption. (CVE-2016-2108 , Important)An overflow bug was discovered in the EVP_EncodeUpdate() function. An attacker could supply very large amounts of input data to overflow a length check, resulting in heap corruption. (CVE-2016-2105 , Low)An overflow bug was discovered in the EVP_EncryptUpdate() function. An attacker could supply very large amounts of input data to overflow a length check, resulting in heap corruption. (CVE-2016-2106 , Low)An issue was discovered in the BIO functions, such as d2i_CMS_bio(), where a short invalid encoding in ASN.1 data can cause allocation of large amounts of memory, potentially resulting in a denial of service. (CVE-2016-2109 , Low)"); 
script_tag(name : "solution", value : "Run yum update openssl to update your system.");
script_tag(name : "solution_type", value : "VendorFix");
script_xref(name : "URL" , value : "https://alas.aws.amazon.com/ALAS-2016-695.html");
script_cve_id("CVE-2016-2105","CVE-2016-2107","CVE-2016-2106","CVE-2016-2109","CVE-2016-2108");
script_tag(name:"cvss_base", value:"10.0");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
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
if ((res = isrpmvuln(pkg:"openssl-static", rpm:"openssl-static~1.0.1k~14.91.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"openssl", rpm:"openssl~1.0.1k~14.91.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"openssl-perl", rpm:"openssl-perl~1.0.1k~14.91.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"openssl-devel", rpm:"openssl-devel~1.0.1k~14.91.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"openssl-debuginfo", rpm:"openssl-debuginfo~1.0.1k~14.91.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);
}
