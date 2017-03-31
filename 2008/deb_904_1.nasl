# OpenVAS Vulnerability Test
# $Id: deb_904_1.nasl 4041 2016-09-13 05:15:17Z teissa $
# Description: Auto-generated from advisory DSA 904-1
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
tag_solution = "For the stable distribution (sarge) these problems have been fixed in
version 10.0-8sarge2.

For the unstable distribution (sid) these problems will be fixed in
version 10.0-11.

We recommend that you upgrade your netpbm package.

 https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20904-1";
tag_summary = "The remote host is missing an update to netpbm-free
announced via advisory DSA 904-1.

Greg Roelofs discovered and fixed several buffer overflows in pnmtopng
which is also included in netpbm, a collection of graphic conversion
utilities, that can lead to the execution of arbitrary code via a
specially crafted PNM file.

For the old stable distribution (woody) these problems have been fixed in
version 9.20-8.5.";


if(description)
{
 script_id(55900);
 script_version("$Revision: 4041 $");
 script_tag(name:"last_modification", value:"$Date: 2016-09-13 07:15:17 +0200 (Tue, 13 Sep 2016) $");
 script_tag(name:"creation_date", value:"2008-01-17 23:07:13 +0100 (Thu, 17 Jan 2008)");
 script_bugtraq_id(15514);
 script_cve_id("CVE-2005-3632");
 script_tag(name:"cvss_base", value:"4.6");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
 script_name("Debian Security Advisory DSA 904-1 (netpbm-free)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2005 E-Soft Inc. http://www.securityspace.com");
 script_family("Debian Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("HostDetails/OS/cpe:/o:debian:debian_linux", "login/SSH/success", "ssh/login/packages");
 script_tag(name : "solution" , value : tag_solution);
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
if ((res = isdpkgvuln(pkg:"libnetpbm9", ver:"9.20-8.5", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libnetpbm9-dev", ver:"9.20-8.5", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"netpbm", ver:"9.20-8.5", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libnetpbm10", ver:"10.0-8sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libnetpbm10-dev", ver:"10.0-8sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libnetpbm9", ver:"10.0-8sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libnetpbm9-dev", ver:"10.0-8sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"netpbm", ver:"10.0-8sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
