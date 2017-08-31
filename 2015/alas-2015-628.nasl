# OpenVAS Vulnerability Test 
# Description: Amazon Linux security check 
# $Id: alas-2015-628.nasl 6575 2017-07-06 13:42:08Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.120618");
script_version("$Revision: 6575 $");
script_tag(name:"creation_date", value:"2015-12-15 02:51:29 +0200 (Tue, 15 Dec 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 15:42:08 +0200 (Thu, 06 Jul 2017) $");
script_name("Amazon Linux Local Check: alas-2015-628");
script_tag(name: "insight", value: "A denial of service flaw was found in the way the libxml2 library parsed certain XML files. An attacker could provide a specially crafted XML file that, when parsed by an application using libxml2, could cause that application to use an excessive amount of memory.The xmlParseConditionalSections function in parser.c in libxml2 does not properly skip intermediary entities when it stops parsing invalid input, which allows context-dependent attackers to cause a denial of service (out-of-bounds read and crash) via crafted XML data, a different vulnerability than CVE-2015-7941 .libxml2 2.9.2 does not properly stop parsing invalid input, which allows context-dependent attackers to cause a denial of service (out-of-bounds read and libxml2 crash) via crafted XML data to the (1) xmlParseEntityDecl or (2) xmlParseConditionalSections function in parser.c, as demonstrated by non-terminated entities.A heap-based buffer overflow vulnerability was found in xmlDictComputeFastQKey in dict.c.A heap-based buffer overflow read in xmlParseMisc was found.A heap-based buffer overflow was found in xmlGROW allowing the attacker to read the memory out of bounds.A buffer overread in xmlNextChar was found, causing segmentation fault when compiled with ASAN.Heap-based buffer overflow was found in xmlParseXmlDecl. When conversion failure happens, parser continues to extract more errors which may lead to unexpected behaviour.Stack-based buffer overread vulnerability with HTML parser in push mode in xmlSAX2TextNode causing segmentation fault when compiled with ASAN.A vulnerability in libxml2 was found causing DoS by exhausting CPU when parsing specially crafted XML document.An out-of-bounds heap read in xmlParseXMLDecl happens when a file containing unfinished xml declaration."); 
script_tag(name : "solution", value : "Run yum update libxml2 to update your system.");
script_tag(name : "solution_type", value : "VendorFix");
script_xref(name : "URL" , value : "https://alas.aws.amazon.com/ALAS-2015-628.html");
script_cve_id("CVE-2015-7497","CVE-2015-7500","CVE-2015-7499","CVE-2015-8241","CVE-2015-7498","CVE-2015-8242","CVE-2015-1819","CVE-2015-5312","CVE-2015-8317","CVE-2015-7942","CVE-2015-7941");
script_tag(name:"cvss_base", value:"7.1");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
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
if ((res = isrpmvuln(pkg:"libxml2", rpm:"libxml2~2.9.1~6.2.50.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"libxml2-debuginfo", rpm:"libxml2-debuginfo~2.9.1~6.2.50.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"libxml2-python26", rpm:"libxml2-python26~2.9.1~6.2.50.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"libxml2-python27", rpm:"libxml2-python27~2.9.1~6.2.50.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"libxml2-devel", rpm:"libxml2-devel~2.9.1~6.2.50.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"libxml2-static", rpm:"libxml2-static~2.9.1~6.2.50.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);
}
