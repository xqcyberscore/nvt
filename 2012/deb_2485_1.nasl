# OpenVAS Vulnerability Test
# $Id: deb_2485_1.nasl 5977 2017-04-19 09:02:22Z teissa $
# Description: Auto-generated from advisory DSA 2485-1 (imp4)
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
tag_insight = "Multiple cross-site scripting (XSS) vulnerabilities were discovered in
IMP, the webmail component in the Horde framework. The vulnerabilities
allow remote attackers to inject arbitrary web script or HTML via various
crafted parameters.

For the stable distribution (squeeze), this problem has been fixed in
version 4.3.7+debian0-2.2.

For the testing distribution (wheezy) and unstable distribution (sid),
this problem will be fixed soon.

We recommend that you upgrade your imp4 packages.";
tag_summary = "The remote host is missing an update to imp4
announced via advisory DSA 2485-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202485-1";

if(description)
{
 script_id(71463);
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_cve_id("CVE-2012-0791");
 script_version("$Revision: 5977 $");
 script_tag(name:"last_modification", value:"$Date: 2017-04-19 11:02:22 +0200 (Wed, 19 Apr 2017) $");
 script_tag(name:"creation_date", value:"2012-08-10 02:56:45 -0400 (Fri, 10 Aug 2012)");
 script_name("Debian Security Advisory DSA 2485-1 (imp4)");



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
if((res = isdpkgvuln(pkg:"imp4", ver:"4.3.7+debian0-2.2", rls:"DEB6.0")) != NULL) {
    report += res;
}

if(report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
