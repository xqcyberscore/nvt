# OpenVAS Vulnerability Test
# $Id: deb_1654_1.nasl 3925 2016-09-01 04:57:14Z teissa $
# Description: Auto-generated from advisory DSA 1654-1 (libxml2)
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
tag_insight = "It was discovered that libxml2, the GNOME XML library, didn't correctly
handle long entity names.  This could allow the execution of arbitrary
code via a malicious XML file.

For the stable distribution (etch), this problem has been fixed in version
2.6.27.dfsg-5.

For the unstable distribution (sid), this problem has been fixed in
version 2.6.32.dfsg-4.

We recommend that you upgrade your libxml2 package.";
tag_summary = "The remote host is missing an update to libxml2
announced via advisory DSA 1654-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201654-1";


if(description)
{
 script_id(61776);
 script_version("$Revision: 3925 $");
 script_tag(name:"last_modification", value:"$Date: 2016-09-01 06:57:14 +0200 (Thu, 01 Sep 2016) $");
 script_tag(name:"creation_date", value:"2008-11-01 01:55:10 +0100 (Sat, 01 Nov 2008)");
 script_cve_id("CVE-2008-3529");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_name("Debian Security Advisory DSA 1654-1 (libxml2)");



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
if ((res = isdpkgvuln(pkg:"libxml2-doc", ver:"2.6.27.dfsg-5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libxml2", ver:"2.6.27.dfsg-5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libxml2-utils", ver:"2.6.27.dfsg-5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"python-libxml2", ver:"2.6.27.dfsg-5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libxml2-dev", ver:"2.6.27.dfsg-5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libxml2-dbg", ver:"2.6.27.dfsg-5", rls:"DEB4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
