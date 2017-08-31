# OpenVAS Vulnerability Test 
# Description: Amazon Linux security check 
# $Id: alas-2012-42.nasl 6578 2017-07-06 13:44:33Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.120257");
script_version("$Revision: 6578 $");
script_tag(name:"creation_date", value:"2015-09-08 13:21:42 +0200 (Tue, 08 Sep 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 15:44:33 +0200 (Thu, 06 Jul 2017) $");
script_name("Amazon Linux Local Check: ALAS-2012-42");
script_tag(name: "insight", value: "An integer overflow flaw was found in Ghostscript's TrueType bytecode interpreter. An attacker could create a specially-crafted PostScript or PDF file that, when interpreted, could cause Ghostscript to crash or, potentially, execute arbitrary code. (CVE-2009-3743 )It was found that Ghostscript always tried to read Ghostscript system initialization files from the current working directory before checking other directories, even if a search path that did not contain the current working directory was specified with the -I option, or the -P- option was used (to prevent the current working directory being searched first). If a user ran Ghostscript in an attacker-controlled directory containing a system initialization file, it could cause Ghostscript to execute arbitrary PostScript code. (CVE-2010-2055 )Ghostscript included the current working directory in its library search path by default. If a user ran Ghostscript without the -P- option in an attacker-controlled directory containing a specially-crafted PostScript library file, it could cause Ghostscript to execute arbitrary PostScript code. With this update, Ghostscript no longer searches the current working directory for library files by default. (CVE-2010-4820 )Note: The fix for CVE-2010-4820  could possibly break existing configurations. To use the previous, vulnerable behavior, run Ghostscript with the -P option (to always search the current working directory first).A flaw was found in the way Ghostscript interpreted PostScript Type 1 and PostScript Type 2 font files. An attacker could create a specially-crafted PostScript Type 1 or PostScript Type 2 font file that, when interpreted, could cause Ghostscript to crash or, potentially, execute arbitrary code. (CVE-2010-4054 )"); 
script_tag(name : "solution", value : "Run yum update ghostscript to update your system.");
script_tag(name : "solution_type", value : "VendorFix");
script_xref(name : "URL" , value : "https://alas.aws.amazon.com/ALAS-2012-42.html");
script_cve_id("CVE-2010-4820", "CVE-2009-3743", "CVE-2010-2055", "CVE-2010-4054");
script_tag(name:"cvss_base", value:"9.3");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
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
if ((res = isrpmvuln(pkg:"ghostscript-doc", rpm:"ghostscript-doc~8.70~11.20.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"ghostscript-debuginfo", rpm:"ghostscript-debuginfo~8.70~11.20.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"ghostscript-devel", rpm:"ghostscript-devel~8.70~11.20.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"ghostscript", rpm:"ghostscript~8.70~11.20.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);
}
