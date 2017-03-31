# OpenVAS Vulnerability Test
# $Id: deb_2091_1.nasl 5245 2017-02-09 08:57:08Z teissa $
# Description: Auto-generated from advisory DSA 2091-1 (squirrelmail)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2010 E-Soft Inc. http://www.securityspace.com
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
tag_insight = "SquirrelMail, a webmail application, does not employ a user-specific token
for webforms. This allows a remote attacker to perform a Cross Site Request
Forgery (CSRF) attack. The attacker may hijack the authentication of
unspecified victims and send messages or change user preferences among other
actions, by tricking the victim into following a link controlled by the
offender.

In addition, a denial-of-service was fixed, which could be triggered when a
passwords containing 8-bit characters was used to log in (CVE-2010-2813).

For the stable distribution (lenny), these problems have been fixed in
version 1.4.15-4+lenny3.1.

For the testing distribution (squeeze) and the unstable distribution (sid),
these problems have been fixed in version 1.4.21-1.

We recommend that you upgrade your squirrelmail packages.";
tag_summary = "The remote host is missing an update to squirrelmail
announced via advisory DSA 2091-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202091-1";


if(description)
{
 script_id(67845);
 script_version("$Revision: 5245 $");
 script_tag(name:"last_modification", value:"$Date: 2017-02-09 09:57:08 +0100 (Thu, 09 Feb 2017) $");
 script_tag(name:"creation_date", value:"2010-08-21 08:54:16 +0200 (Sat, 21 Aug 2010)");
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_cve_id("CVE-2009-2964", "CVE-2010-2813");
 script_name("Debian Security Advisory DSA 2091-1 (squirrelmail)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2010 E-Soft Inc. http://www.securityspace.com");
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
if ((res = isdpkgvuln(pkg:"squirrelmail", ver:"1.4.15-4+lenny3.1", rls:"DEB5.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
