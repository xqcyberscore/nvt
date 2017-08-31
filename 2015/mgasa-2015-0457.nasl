# OpenVAS Vulnerability Test 
# Description: Mageia Linux security check 
# $Id: mgasa-2015-0457.nasl 6600 2017-07-07 09:58:31Z teissa $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.131140");
script_version("$Revision: 6600 $");
script_tag(name:"creation_date", value:"2015-11-27 11:00:03 +0200 (Fri, 27 Nov 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-07 11:58:31 +0200 (Fri, 07 Jul 2017) $");
script_name("Mageia Linux Local Check: mgasa-2015-0457");
script_tag(name: "insight", value: "Updated libxml2 packages fix security vulnerabilities: In libxml2 before 2.9.3, one case where when dealing with entities expansion, it failed to exit, leading to a denial of service (CVE-2015-5312). In libxml2 before 2.9.3, it was possible to hit a negative offset in the name indexing used to randomize the dictionary key generation, causing a heap buffer overflow in xmlDictComputeFastQKey (CVE-2015-7497). In libxml2 before 2.9.3, after encoding conversion failures, the parser was continuing to process to extract more errors, which can potentially lead to unexpected behaviour (CVE-2015-7498). In libxml2 before 2.9.3, the parser failed to detect a case where the current pointer to the input was out of range, leaving it in an incoherent state (CVE-2015-7499). In libxml2 before 2.9.3, a memory access error could happen while processing a start tag due to incorrect entities boundaries (CVE-2015-7500). In libxml2 before 2.9.3, a buffer overread in xmlNextChar due to extra processing of MarkupDecl after EOF has been reached (CVE-2015-8241). In libxml2 before 2.9.3, stack-basedb uffer overead with HTML parser in push mode (CVE-2015-8242). In libxml2 before 2.9.3, out of bounds heap reads could happen due to failure processing the encoding declaration of the XMLDecl in xmlParseEncodingDecl (CVE-2015-8317)."); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_xref(name : "URL" , value : "https://advisories.mageia.org/MGASA-2015-0457.html");
script_cve_id("CVE-2015-5312","CVE-2015-7497","CVE-2015-7498","CVE-2015-7499","CVE-2015-7500","CVE-2015-8241","CVE-2015-8242","CVE-2015-8317");
script_tag(name:"cvss_base", value:"7.1");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
script_tag(name:"qod_type", value:"package");
script_dependencies("gather-package-list.nasl");
script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release");
script_category(ACT_GATHER_INFO);
script_tag(name : "summary", value : "Mageia Linux Local Security Checks mgasa-2015-0457");
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
if ((res = isrpmvuln(pkg:"libxml2", rpm:"libxml2~2.9.3~1.mga5", rls:"MAGEIA5")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);
}
