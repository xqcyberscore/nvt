# OpenVAS Vulnerability Test
# $Id: esoft_slk_ssa_2006_114_01.nasl 9352 2018-04-06 07:13:02Z cfischer $
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
tag_insight = "New Mozilla packages are available for Slackware 10.0, 10.1,
10.2 and -current to fix multiple security issues.

More details about the issues may be found here:

http://www.mozilla.org/projects/security/known-vulnerabilities.html#mozilla

Also note that this release marks the EOL (End Of Life) for the Mozilla
Suite series.  It's been a great run, so thanks to everyone who put in
so much effort to make Mozilla a great browser suite.  In the next
Slackware release fans of the Mozilla Suite will be able to look
forward to browsing with SeaMonkey, the Suite's successor.  Anyone
using an older version of Slackware may want to start thinking about
migrating to another browser -- if not now, when the next problems
with Mozilla are found.

Although the 'sunset announcement' states that mozilla-1.7.13 is the
final mozilla release, I wouldn't be too surprised to see just one
more since there's a Makefile.in bug that needed to be patched here
before Mozilla 1.7.13 would build.  If a new release comes out and
fixes only that issue, don't look for a package release on that as
it's already fixed in these packages.  If additional issues are
fixed, then there will be new packages.  Basically, if upstream
un-EOLs this for a good reason, so will we.";
tag_summary = "The remote host is missing an update as announced
via advisory SSA:2006-114-01.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=SSA:2006-114-01";
                                                                                
if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.56693");
 script_tag(name:"creation_date", value:"2012-09-11 01:34:21 +0200 (Tue, 11 Sep 2012)");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"cvss_base", value:"6.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
 script_version("$Revision: 9352 $");
 name = "Slackware Advisory SSA:2006-114-01 mozilla security/EOL ";
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
if(isslkpkgvuln(pkg:"mozilla", ver:"1.7.13-i486-1", rls:"SLK10.0")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"mozilla-plugins", ver:"1.7.13-noarch-1", rls:"SLK10.0")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"mozilla", ver:"1.7.13-i486-1", rls:"SLK10.1")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"mozilla-plugins", ver:"1.7.13-noarch-1", rls:"SLK10.1")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"mozilla", ver:"1.7.13-i486-1", rls:"SLK10.2")) {
    vuln = 1;
}

if(vuln) {
    security_message(0);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
