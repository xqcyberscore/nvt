# OpenVAS Vulnerability Test
# $Id: deb_2414_1.nasl 9352 2018-04-06 07:13:02Z cfischer $
# Description: Auto-generated from advisory DSA 2414-1 (fex)
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
tag_insight = "Nicola Fioravanti discovered that F*X, a web service for transferring
very large files, is not properly sanitizing input parameters of the fup
script.  An attacker can use this flaw to conduct reflected cross-site
scripting attacks via various script parameters.

For the stable distribution (squeeze), this problem has been fixed in
version 20100208+debian1-1+squeeze2.

For the testing distribution (wheezy), this problem will be fixed soon.

For the unstable distribution (sid), this problem has been fixed
in version 20120215-1.

We recommend that you upgrade your fex packages.";
tag_summary = "The remote host is missing an update to fex
announced via advisory DSA 2414-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202414-1";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.71141");
 script_cve_id("CVE-2012-0869");
 script_version("$Revision: 9352 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2012-03-12 11:31:28 -0400 (Mon, 12 Mar 2012)");
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_name("Debian Security Advisory DSA 2414-1 (fex)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com");
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
if((res = isdpkgvuln(pkg:"fex", ver:"20100208+debian1-1+squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"fex-utils", ver:"20100208+debian1-1+squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}

if(report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
