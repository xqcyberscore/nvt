# OpenVAS Vulnerability Test 
# Description: Amazon Linux security check 
# $Id: alas-2012-40.nasl 6578 2017-07-06 13:44:33Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.120255");
script_version("$Revision: 6578 $");
script_tag(name:"creation_date", value:"2015-09-08 13:21:38 +0200 (Tue, 08 Sep 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 15:44:33 +0200 (Thu, 06 Jul 2017) $");
script_name("Amazon Linux Local Check: ALAS-2012-40");
script_tag(name: "insight", value: "Two heap-based buffer overflow flaws were found in the way t1lib processed Adobe Font Metrics (AFM) files. If a specially-crafted font file was opened by an application linked against t1lib, it could cause the application to crash or, potentially, execute arbitrary code with the privileges of the user running the application. (CVE-2010-2642 , CVE-2011-0433 )An invalid pointer dereference flaw was found in t1lib. A specially-crafted font file could, when opened, cause an application linked against t1lib to crash or, potentially, execute arbitrary code with the privileges of the user running the application. (CVE-2011-0764 )A use-after-free flaw was found in t1lib. A specially-crafted font file could, when opened, cause an application linked against t1lib to crash or, potentially, execute arbitrary code with the privileges of the user running the application. (CVE-2011-1553 )An off-by-one flaw was found in t1lib. A specially-crafted font file could, when opened, cause an application linked against t1lib to crash or, potentially, execute arbitrary code with the privileges of the user running the application. (CVE-2011-1554 )An out-of-bounds memory read flaw was found in t1lib. A specially-crafted font file could, when opened, cause an application linked against t1lib to crash. (CVE-2011-1552 )"); 
script_tag(name : "solution", value : "Run yum update t1lib to update your system.");
script_tag(name : "solution_type", value : "VendorFix");
script_xref(name : "URL" , value : "https://alas.aws.amazon.com/ALAS-2012-40.html");
script_cve_id("CVE-2011-1552", "CVE-2011-1553", "CVE-2011-0764", "CVE-2010-2642", "CVE-2011-1554");
script_tag(name:"cvss_base", value:"7.6");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
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
if ((res = isrpmvuln(pkg:"t1lib-debuginfo", rpm:"t1lib-debuginfo~5.1.2~6.5.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"t1lib", rpm:"t1lib~5.1.2~6.5.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"t1lib-static", rpm:"t1lib-static~5.1.2~6.5.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"t1lib-devel", rpm:"t1lib-devel~5.1.2~6.5.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"t1lib-apps", rpm:"t1lib-apps~5.1.2~6.5.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);
}
