# OpenVAS Vulnerability Test
# $Id: deb_2135_1.nasl 6613 2017-07-07 12:08:40Z cfischer $
# Description: Auto-generated from advisory DSA 2135-1 (xpdf)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com
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
tag_insight = "Joel Voss of Leviathan Security Group discovered two vulnerabilities
in xpdf rendering engine, which may lead to the execution of arbitrary
code if a malformed PDF file is opened.

For the stable distribution (lenny), these problems have been fixed in
version 3.02-1.4+lenny3.

For the upcoming stable distribution (squeeze) and the unstable
distribution (sid), these problems don't apply, since xpdf has been 
patched to use the Poppler PDF library.

We recommend that you upgrade your poppler packages.";
tag_summary = "The remote host is missing an update to xpdf
announced via advisory DSA 2135-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202135-1";


if(description)
{
 script_id(68977);
 script_version("$Revision: 6613 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:08:40 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2011-03-07 16:04:02 +0100 (Mon, 07 Mar 2011)");
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_cve_id("CVE-2010-3702", "CVE-2010-3704");
 script_name("Debian Security Advisory DSA 2135-1 (xpdf)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com");
 script_family("Debian Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages");
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
if ((res = isdpkgvuln(pkg:"xpdf", ver:"3.02-1.4+lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xpdf-common", ver:"3.02-1.4+lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xpdf-reader", ver:"3.02-1.4+lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xpdf-utils", ver:"3.02-1.4+lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
