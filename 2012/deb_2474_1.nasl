# OpenVAS Vulnerability Test
# $Id: deb_2474_1.nasl 2944 2016-03-24 09:32:58Z benallard $
# Description: Auto-generated from advisory DSA 2474-1 (ikiwiki)
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
tag_insight = "R Benencia discovered that ikiwiki, a wiki compiler, does not
properly escape the author (and its URL) of certain metadata, such as
comments. This might be used to conduct cross-site scripting attacks.

For the stable distribution (squeeze), this problem has been fixed in
version 3.20100815.9.

For the testing distribution (wheezy), this problem will be fixed soon.

For the unstable distribution (sid), this problem has been fixed in
version 3.20120516.

We recommend that you upgrade your ikiwiki packages.";
tag_summary = "The remote host is missing an update to ikiwiki
announced via advisory DSA 2474-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202474-1";

if(description)
{
 script_id(71352);
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_cve_id("CVE-2012-0220");
 script_version("$Revision: 2944 $");
 script_tag(name:"last_modification", value:"$Date: 2016-03-24 10:32:58 +0100 (Thu, 24 Mar 2016) $");
 script_tag(name:"creation_date", value:"2012-05-31 11:51:21 -0400 (Thu, 31 May 2012)");
 script_name("Debian Security Advisory DSA 2474-1 (ikiwiki)");


 script_summary("Debian Security Advisory DSA 2474-1 (ikiwiki)");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com");
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
if((res = isdpkgvuln(pkg:"ikiwiki", ver:"3.20100815.9", rls:"DEB6.0")) != NULL) {
    report += res;
}

if(report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
