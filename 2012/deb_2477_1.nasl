# OpenVAS Vulnerability Test
# $Id: deb_2477_1.nasl 8671 2018-02-05 16:38:48Z teissa $
# Description: Auto-generated from advisory DSA 2477-1 (sympa)
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
tag_insight = "Several vulnerabilities have been discovered in Sympa, a mailing list
manager, that allow to skip the scenario-based authorization
mechanisms. This vulnerability allows to display the archives
management page, and download and delete the list archives by
unauthorized users.

For the stable distribution (squeeze), this problem has been fixed in
version 6.0.1+dfsg-4+squeeze1.

For the testing distribution (wheezy), this problem will be fixed
soon.

For the unstable distribution (sid), this problem has been fixed in
version 6.1.11~dfsg-2.

We recommend that you upgrade your sympa packages.";
tag_summary = "The remote host is missing an update to sympa
announced via advisory DSA 2477-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202477-1";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.71355");
 script_cve_id("CVE-2012-2352");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_version("$Revision: 8671 $");
 script_tag(name:"last_modification", value:"$Date: 2018-02-05 17:38:48 +0100 (Mon, 05 Feb 2018) $");
 script_tag(name:"creation_date", value:"2012-05-31 11:51:39 -0400 (Thu, 31 May 2012)");
 script_name("Debian Security Advisory DSA 2477-1 (sympa)");



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
if((res = isdpkgvuln(pkg:"sympa", ver:"6.0.1+dfsg-4+squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}

if(report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
