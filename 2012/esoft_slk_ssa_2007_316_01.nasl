# OpenVAS Vulnerability Test
# $Id: esoft_slk_ssa_2007_316_01.nasl 9352 2018-04-06 07:13:02Z cfischer $
# Description: Auto-generated from the corresponding slackware advisory
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# or at your option, GNU General Public License version 3,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

include("revisions-lib.inc");
tag_insight = "New xpdf packages are available for Slackware 9.1, 10.0, 10.1, 10.2, 11.0,
12.0, and -current.  New poppler packages are available for Slackware 12.0
and -current.  New koffice packages are available for Slackware 11.0, 12.0,
and -current.  New kdegraphics packages are available for Slackware 10.2,
11.0, 12.0, and -current.

These updated packages address similar bugs which could be used to crash
applications linked with poppler or that use code from xpdf through the
use of a malformed PDF document.  It is possible that a maliciously
crafted document could cause code to be executed in the context of the
user running the application processing the PDF.

This advisoriy cover the bugs:
http://www.kde.org/info/security/advisory-20071107-1.txt";
tag_summary = "The remote host is missing an update as announced
via advisory SSA:2007-316-01.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=SSA:2007-316-01";
                                                                                
if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.59020");
 script_tag(name:"creation_date", value:"2012-09-11 01:34:21 +0200 (Tue, 11 Sep 2012)");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
 script_cve_id("CVE-2007-3387", "CVE-2007-4352", "CVE-2007-5392", "CVE-2007-5393");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_version("$Revision: 9352 $");
 name = "Slackware Advisory SSA:2007-316-01 xpdf/poppler/koffice/kdegraphics ";
 script_name(name);



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com");
 script_family("Slackware Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "insight" , value : tag_insight);
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name:"qod_type", value:"package");
 script_tag(name:"solution_type", value:"VendorFix");
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-slack.inc");
vuln = 0;
if(isslkpkgvuln(pkg:"xpdf", ver:"3.02pl2-i486-1_slack9.1", rls:"SLK9.1")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"xpdf", ver:"3.02pl2-i486-1_slack10.0", rls:"SLK10.0")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"xpdf", ver:"3.02pl2-i486-1_slack10.1", rls:"SLK10.1")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"kdegraphics", ver:"3.4.2-i486-3_slack10.2", rls:"SLK10.2")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"xpdf", ver:"3.02pl2-i486-1_slack10.2", rls:"SLK10.2")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"kdegraphics", ver:"3.5.4-i486-2_slack11.0", rls:"SLK11.0")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"koffice", ver:"1.5.2-i486-5_slack11.0", rls:"SLK11.0")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"xpdf", ver:"3.02pl2-i486-1_slack11.0", rls:"SLK11.0")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"kdegraphics", ver:"3.5.7-i486-2_slack12.0", rls:"SLK12.0")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"poppler", ver:"0.6.2-i486-1_slack12.0", rls:"SLK12.0")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"koffice", ver:"1.6.3-i486-2_slack12.0", rls:"SLK12.0")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"xpdf", ver:"3.02pl2-i486-1_slack12.0", rls:"SLK12.0")) {
    vuln = 1;
}

if(vuln) {
    security_message(0);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
