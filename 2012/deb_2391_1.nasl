# OpenVAS Vulnerability Test
# $Id: deb_2391_1.nasl 2944 2016-03-24 09:32:58Z benallard $
# Description: Auto-generated from advisory DSA 2391-1 (phpmyadmin)
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
tag_insight = "Several vulnerabilities have been discovered in phpMyAdmin, a tool
to administer MySQL over the web. The Common Vulnerabilities and
Exposures project identifies the following problems:

CVE-2011-4107

The XML import plugin allowed a remote attacker to read arbitrary
files via XML data containing external entity references.

CVE-2011-1940, CVE-2011-3181

Cross site scripting was possible in the table tracking feature,
allowing a remote attacker to inject arbitrary web script or HTML.


The oldstable distribution (lenny) is not affected by these problems.

For the stable distribution (squeeze), these problems have been fixed
in version 4:3.3.7-7.

For the testing distribution (wheezy) and unstable distribution (sid),
these problems have been fixed in version 4:3.4.7.1-1.

We recommend that you upgrade your phpmyadmin packages.";
tag_summary = "The remote host is missing an update to phpmyadmin
announced via advisory DSA 2391-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202391-1";

if(description)
{
 script_id(70709);
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_cve_id("CVE-2011-1940", "CVE-2011-3181", "CVE-2011-4107");
 script_version("$Revision: 2944 $");
 script_tag(name:"last_modification", value:"$Date: 2016-03-24 10:32:58 +0100 (Thu, 24 Mar 2016) $");
 script_tag(name:"creation_date", value:"2012-02-11 03:28:19 -0500 (Sat, 11 Feb 2012)");
 script_name("Debian Security Advisory DSA 2391-1 (phpmyadmin)");

 script_summary("Debian Security Advisory DSA 2391-1 (phpmyadmin)");

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
if((res = isdpkgvuln(pkg:"phpmyadmin", ver:"4:3.3.7-7", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"phpmyadmin", ver:"4:3.4.9-1", rls:"DEB7.0")) != NULL) {
    report += res;
}

if(report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
