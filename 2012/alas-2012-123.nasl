# OpenVAS Vulnerability Test 
# Description: Amazon Linux security check 
# $Id: alas-2012-123.nasl 6578 2017-07-06 13:44:33Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.120479");
script_version("$Revision: 6578 $");
script_tag(name:"creation_date", value:"2015-09-08 13:27:23 +0200 (Tue, 08 Sep 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 15:44:33 +0200 (Thu, 06 Jul 2017) $");
script_name("Amazon Linux Local Check: ALAS-2012-123");
script_tag(name: "insight", value: "A heap-based buffer overflow flaw was found in the way libxslt applied templates to nodes selected by certain namespaces. An attacker could use this flaw to create a malicious XSL file that, when used by an application linked against libxslt to perform an XSL transformation, could cause the application to crash or, possibly, execute arbitrary code with the privileges of the user running the application. (CVE-2012-2871 )Several denial of service flaws were found in libxslt. An attacker could use these flaws to create a malicious XSL file that, when used by an application linked against libxslt to perform an XSL transformation, could cause the application to crash. (CVE-2012-2825 , CVE-2012-2870 , CVE-2011-3970 )An information leak could occur if an application using libxslt processed an untrusted XPath expression, or used a malicious XSL file to perform an XSL transformation. If combined with other flaws, this leak could possibly help an attacker bypass intended memory corruption protections. (CVE-2011-1202 )"); 
script_tag(name : "solution", value : "Run yum update libxslt to update your system.");
script_tag(name : "solution_type", value : "VendorFix");
script_xref(name : "URL" , value : "https://alas.aws.amazon.com/ALAS-2012-123.html");
script_cve_id("CVE-2011-1202", "CVE-2011-3970", "CVE-2012-2871", "CVE-2012-2870", "CVE-2012-2825");
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
if ((res = isrpmvuln(pkg:"libxslt-python", rpm:"libxslt-python~1.1.26~2.7.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"libxslt", rpm:"libxslt~1.1.26~2.7.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"libxslt-devel", rpm:"libxslt-devel~1.1.26~2.7.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"libxslt-debuginfo", rpm:"libxslt-debuginfo~1.1.26~2.7.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);
}
