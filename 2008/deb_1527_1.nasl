# OpenVAS Vulnerability Test
# $Id: deb_1527_1.nasl 3913 2016-08-31 08:01:39Z teissa $
# Description: Auto-generated from advisory DSA 1527-1 (debian-goodies)
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
tag_insight = "Thomas de Grenier de Latour discovered that the checkrestart tool in the
debian-goodies suite of utilities, allowed local users to gain privileges
via shell metacharacters in the name of the executable file for a running
process.

For the stable distribution (etch), this problem has been fixed in
version 0.27+etch1.

For the old stable distribution (sarge), this problem has been fixed in
version 0.23+sarge1.

For the unstable distribution (sid), this problem has been fixed in
version 0.34.

We recommend that you upgrade your debian-goodies package.";
tag_summary = "The remote host is missing an update to debian-goodies
announced via advisory DSA 1527-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201527-1";


if(description)
{
 script_id(60617);
 script_version("$Revision: 3913 $");
 script_tag(name:"last_modification", value:"$Date: 2016-08-31 10:01:39 +0200 (Wed, 31 Aug 2016) $");
 script_tag(name:"creation_date", value:"2008-03-27 18:25:13 +0100 (Thu, 27 Mar 2008)");
 script_cve_id("CVE-2007-3912");
 script_tag(name:"cvss_base", value:"7.2");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_name("Debian Security Advisory DSA 1527-1 (debian-goodies)");



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
if ((res = isdpkgvuln(pkg:"debian-goodies", ver:"0.23+sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"debian-goodies", ver:"0.27+etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
