# OpenVAS Vulnerability Test
# $Id: esoft_slk_ssa_2006_129_01.nasl 9352 2018-04-06 07:13:02Z cfischer $
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
tag_insight = "New Apache packages are available for Slackware 8.1, 9.0, 9.1, 10.0, 10.1,
10.2, and -current to fix security issues.

In addition, new mod_ssl packages for Apache 1.3.35 are available for
all of these versions of Slackware, and new versions of PHP are
available for Slackware -current.  These additional packages do not
fix security issues, but may be required on your system depending on
your Apache setup.

One more note about this round of updates:  the packages have been given
build versions that indicate which version of Slackware they are meant
to patch, such as -1_slack8.1, or -1_slack9.0, etc.  This should help to
avoid some of the issues with automatic upgrade tools by providing a
unique package name when the same fix is deployed across multiple
Slackware versions.  Only patches applied to -current will have the
simple build number, such as -1.";
tag_summary = "The remote host is missing an update as announced
via advisory SSA:2006-129-01.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=SSA:2006-129-01";
                                                                                
if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.56731");
 script_tag(name:"creation_date", value:"2012-09-11 01:34:21 +0200 (Tue, 11 Sep 2012)");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
 script_bugtraq_id(15834);
 script_cve_id("CVE-2005-3352");
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_version("$Revision: 9352 $");
 name = "Slackware Advisory SSA:2006-129-01 Apache httpd ";
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
if(isslkpkgvuln(pkg:"apache", ver:"1.3.35-i386-1_slack8.1", rls:"SLK8.1")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"mod_ssl", ver:"2.8.26_1.3.35-i386-1_slack8.1", rls:"SLK8.1")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"apache", ver:"1.3.35-i386-1_slack9.0", rls:"SLK9.0")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"mod_ssl", ver:"2.8.26_1.3.35-i386-1_slack9.0", rls:"SLK9.0")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"apache", ver:"1.3.35-i486-1_slack9.1", rls:"SLK9.1")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"mod_ssl", ver:"2.8.26_1.3.35-i486-1_slack9.1", rls:"SLK9.1")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"apache", ver:"1.3.35-i486-1_slack10.0", rls:"SLK10.0")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"mod_ssl", ver:"2.8.26_1.3.35-i486-1_slack10.0", rls:"SLK10.0")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"apache", ver:"1.3.35-i486-1_slack10.1", rls:"SLK10.1")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"mod_ssl", ver:"2.8.26_1.3.35-i486-1_slack10.1", rls:"SLK10.1")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"apache", ver:"1.3.35-i486-1_slack10.2", rls:"SLK10.2")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"mod_ssl", ver:"2.8.26_1.3.35-i486-1_slack10.2", rls:"SLK10.2")) {
    vuln = 1;
}

if(vuln) {
    security_message(0);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
