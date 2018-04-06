# OpenVAS Vulnerability Test
# $Id: esoft_slk_ssa_2005_170_01.nasl 9352 2018-04-06 07:13:02Z cfischer $
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
tag_insight = "Sun has released a couple of security advisories pertaining to both the
Java Runtime Environment and the Standard Edition Development Kit.
These could allow applets to read or write to local files.  For more
details, Sun's advisories may be found here:

  http://sunsolve.sun.com/search/document.do?assetkey=1-26-101748-1
  http://sunsolve.sun.com/search/document.do?assetkey=1-26-101749-1

Slackware repackage's Sun's Java(TM) binaries without changing them, so
the packages from Slackware -current should be used for all glibc based
Slackware versions.";
tag_summary = "The remote host is missing an update as announced
via advisory SSA:2005-170-01.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=SSA:2005-170-01";
                                                                                
if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.53965");
 script_tag(name:"creation_date", value:"2012-09-11 01:34:21 +0200 (Tue, 11 Sep 2012)");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"cvss_base", value:"6.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
 script_version("$Revision: 9352 $");
 name = "Slackware Advisory SSA:2005-170-01 New Java packages";
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

if(isslkpkgvuln(pkg:"j2sdk", ver:"1_5_0_03-i586-1", rls:"SLK8.1")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"jre", ver:"1_5_0_03-i586-1", rls:"SLK8.1")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"j2sdk", ver:"1_5_0_03-i586-1", rls:"SLK9.0")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"jre", ver:"1_5_0_03-i586-1", rls:"SLK9.0")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"j2sdk", ver:"1_5_0_03-i586-1", rls:"SLK9.1")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"jre", ver:"1_5_0_03-i586-1", rls:"SLK9.1")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"j2sdk", ver:"1_5_0_03-i586-1", rls:"SLK10.0")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"jre", ver:"1_5_0_03-i586-1", rls:"SLK10.0")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"j2sdk", ver:"1_5_0_03-i586-1", rls:"SLK10.1")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"jre", ver:"1_5_0_03-i586-1", rls:"SLK10.1")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"j2sdk", ver:"1_5_0_03-i586-1", rls:"SLK8.1")) {
    vuln = 1;
}

if(vuln) {
    security_message(0);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
