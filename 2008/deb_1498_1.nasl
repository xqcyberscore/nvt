# OpenVAS Vulnerability Test
# $Id: deb_1498_1.nasl 3907 2016-08-30 05:36:48Z teissa $
# Description: Auto-generated from advisory DSA 1498-1 (libimager-perl)
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
tag_insight = "It was discovered that libimager-perl, a Perl extension for Generating 24
bit images, did not correctly handle 8-bit per-pixel compressed images,
which could allow the execution of arbitrary code.

For the stable distribution, this problem has been fixed in version
0.50-1etch1.

We recommend that you upgrade your libimager-perl package.";
tag_summary = "The remote host is missing an update to libimager-perl
announced via advisory DSA 1498-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201498-1";


if(description)
{
 script_id(60432);
 script_version("$Revision: 3907 $");
 script_tag(name:"last_modification", value:"$Date: 2016-08-30 07:36:48 +0200 (Tue, 30 Aug 2016) $");
 script_tag(name:"creation_date", value:"2008-02-28 02:09:28 +0100 (Thu, 28 Feb 2008)");
 script_cve_id("CVE-2007-2459");
 script_tag(name:"cvss_base", value:"7.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_name("Debian Security Advisory DSA 1498-1 (libimager-perl)");



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
if ((res = isdpkgvuln(pkg:"libimager-perl", ver:"0.50-1etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
