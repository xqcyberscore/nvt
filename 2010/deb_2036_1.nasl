# OpenVAS Vulnerability Test
# $Id: deb_2036_1.nasl 5245 2017-02-09 08:57:08Z teissa $
# Description: Auto-generated from advisory DSA 2036-1 (jasper)
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
tag_insight = "It was discovered that the JasPer JPEG-2000 runtime library allowed an
attacker to create a crafted input file that could lead to denial of
service and heap corruption.

Besides addressing this vulnerability, this updates also addresses a
regression introduced in the security fix for CVE-2008-3521, applied
before Debian Lenny's release, that could cause errors when reading some
JPEG input files.

For the stable distribution (lenny), this problem has been fixed in
version 1.900.1-5.1+lenny1.

For the unstable distribution (sid), this problem has been fixed in
version 1.900.1-6.

We recommend that you upgrade your jasper package.";
tag_summary = "The remote host is missing an update to jasper
announced via advisory DSA 2036-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202036-1";


if(description)
{
 script_id(67269);
 script_version("$Revision: 5245 $");
 script_tag(name:"last_modification", value:"$Date: 2017-02-09 09:57:08 +0100 (Thu, 09 Feb 2017) $");
 script_tag(name:"creation_date", value:"2010-04-21 03:31:17 +0200 (Wed, 21 Apr 2010)");
 script_cve_id("CVE-2007-2721", "CVE-2008-3521");
 script_tag(name:"cvss_base", value:"7.2");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_name("Debian Security Advisory DSA 2036-1 (jasper)");



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
if ((res = isdpkgvuln(pkg:"libjasper-runtime", ver:"1.900.1-5.1+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libjasper1", ver:"1.900.1-5.1+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libjasper-dev", ver:"1.900.1-5.1+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
