# OpenVAS Vulnerability Test
# $Id: deb_166_1.nasl 3925 2016-09-01 04:57:14Z teissa $
# Description: Auto-generated from advisory DSA 166-1
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2007 E-Soft Inc. http://www.securityspace.com
# Text descriptions are largerly excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
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
tag_insight = "Two buffer overflows have been discovered in purity, a game for nerds
and hackers, which is installed setgid games on a Debian system.  This
problem could be exploited to gain unauthorized access to the group
games.  A malicious user could alter the highscore of several games.

This problem has been fixed in version 1-14.2 for the current stable
distribution (woody), in version 1-9.1 for the old stable distribution
(potato) and in version 1-16 for the unstable distribution (sid).

We recommend that you upgrade your purity packages.";
tag_summary = "The remote host is missing an update to purity
announced via advisory DSA 166-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20166-1";

if(description)
{
 script_id(53422);
 script_version("$Revision: 3925 $");
 script_tag(name:"last_modification", value:"$Date: 2016-09-01 06:57:14 +0200 (Thu, 01 Sep 2016) $");
 script_tag(name:"creation_date", value:"2008-01-17 22:24:46 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2002-1124");
 script_tag(name:"cvss_base", value:"7.2");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_name("Debian Security Advisory DSA 166-1 (purity)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2005 E-Soft Inc. http://www.securityspace.com");
 script_family("Debian Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("HostDetails/OS/cpe:/o:debian:debian_linux", "login/SSH/success", "ssh/login/packages");
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

include("pkg-lib-deb.inc");

res = "";
report = "";
if ((res = isdpkgvuln(pkg:"purity", ver:"1-9.1", rls:"DEB2.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"purity", ver:"1-14.2", rls:"DEB3.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
