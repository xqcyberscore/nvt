# OpenVAS Vulnerability Test 
# Description: Amazon Linux security check 
# $Id: alas-2012-48.nasl 6578 2017-07-06 13:44:33Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.120259");
script_version("$Revision: 6578 $");
script_tag(name:"creation_date", value:"2015-09-08 13:21:48 +0200 (Tue, 08 Sep 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 15:44:33 +0200 (Thu, 06 Jul 2017) $");
script_name("Amazon Linux Local Check: ALAS-2012-48");
script_tag(name: "insight", value: "TeX Live embeds a copy of t1lib. The t1lib library allows you to rasterize bitmaps from PostScript Type 1 fonts. The following issues affect t1lib code:Two heap-based buffer overflow flaws were found in the way t1lib processed Adobe Font Metrics (AFM) files. If a specially-crafted font file was opened by a TeX Live utility, it could cause the utility to crash or, potentially, execute arbitrary code with the privileges of the user running the utility. (CVE-2010-2642 , CVE-2011-0433 )An invalid pointer dereference flaw was found in t1lib. A specially-crafted font file could, when opened, cause a TeX Live utility to crash or, potentially, execute arbitrary code with the privileges of the user running the utility. (CVE-2011-0764 )A use-after-free flaw was found in t1lib. A specially-crafted font file could, when opened, cause a TeX Live utility to crash or, potentially, execute arbitrary code with the privileges of the user running the utility. (CVE-2011-1553 )An off-by-one flaw was found in t1lib. A specially-crafted font file could, when opened, cause a TeX Live utility to crash or, potentially, execute arbitrary code with the privileges of the user running the utility. (CVE-2011-1554 )An out-of-bounds memory read flaw was found in t1lib. A specially-crafted font file could, when opened, cause a TeX Live utility to crash. (CVE-2011-1552 )"); 
script_tag(name : "solution", value : "Run yum update texlive to update your system.");
script_tag(name : "solution_type", value : "VendorFix");
script_xref(name : "URL" , value : "https://alas.aws.amazon.com/ALAS-2012-48.html");
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
if ((res = isrpmvuln(pkg:"texlive-dviutils", rpm:"texlive-dviutils~2007~57.9.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"kpathsea", rpm:"kpathsea~2007~57.9.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"texlive-context", rpm:"texlive-context~2007~57.9.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"texlive-afm", rpm:"texlive-afm~2007~57.9.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"mendexk", rpm:"mendexk~2.6e~57.9.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"texlive-xetex", rpm:"texlive-xetex~2007~57.9.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"texlive-east-asian", rpm:"texlive-east-asian~2007~57.9.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"texlive-debuginfo", rpm:"texlive-debuginfo~2007~57.9.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"texlive-utils", rpm:"texlive-utils~2007~57.9.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"texlive-dvips", rpm:"texlive-dvips~2007~57.9.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"texlive-latex", rpm:"texlive-latex~2007~57.9.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"kpathsea-devel", rpm:"kpathsea-devel~2007~57.9.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"texlive", rpm:"texlive~2007~57.9.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);
}
