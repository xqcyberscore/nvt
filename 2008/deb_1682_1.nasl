# OpenVAS Vulnerability Test
# $Id: deb_1682_1.nasl 3939 2016-09-02 05:15:43Z teissa $
# Description: Auto-generated from advisory DSA 1682-1 (squirrelmail)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2008 E-Soft Inc. http://www.securityspace.com
# Text descriptions are largely excerpted from the referenced
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
tag_insight = "Ivan Markovic discovered that SquirrelMail, a webmail application, did not
sufficiently sanitise incoming HTML email, allowing an attacker to perform
cross site scripting through sending a malicious HTML email.

For the stable distribution (etch), this problem has been fixed in
version 1.4.9a-3.

For the unstable distribution (sid), this problem has been fixed in
version 1.4.15-4.

We recommend that you upgrade your squirrelmail package.";
tag_summary = "The remote host is missing an update to squirrelmail
announced via advisory DSA 1682-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201682-1";


if(description)
{
 script_id(62844);
 script_version("$Revision: 3939 $");
 script_tag(name:"last_modification", value:"$Date: 2016-09-02 07:15:43 +0200 (Fri, 02 Sep 2016) $");
 script_tag(name:"creation_date", value:"2008-12-10 05:23:56 +0100 (Wed, 10 Dec 2008)");
 script_cve_id("CVE-2008-2379");
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_name("Debian Security Advisory DSA 1682-1 (squirrelmail)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2008 E-Soft Inc. http://www.securityspace.com");
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
if ((res = isdpkgvuln(pkg:"squirrelmail", ver:"1.4.9a-3", rls:"DEB4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
