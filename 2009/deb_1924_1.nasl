# OpenVAS Vulnerability Test
# $Id: deb_1924_1.nasl 4655 2016-12-01 15:18:13Z teissa $
# Description: Auto-generated from advisory DSA 1924-1 (mahara)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com
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
tag_insight = "Two vulnerabilities have been discovered in, an electronic portfolio,
weblog, and resume builder.  The Common Vulnerabilities and Exposures
project identifies the following problems:

CVE-2009-3298

Ruslan Kabalin discovered a issue with resetting passwords, which could
lead to a privilege escalation of an institutional administrator
account.

CVE-2009-3299

Sven Vetsch discovered a cross-site scripting vulnerability via the
resume fields.


For the stable distribution (lenny), these problems have been fixed in
version 1.0.4-4+lenny4.

The oldstable distribution (etch) does not contain mahara.

For the testing distribution (squeeze) and the unstable distribution
(sid), this problem will be fixed soon.


We recommend that you upgrade your mahara packages.";
tag_summary = "The remote host is missing an update to mahara
announced via advisory DSA 1924-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201924-1";


if(description)
{
 script_id(66204);
 script_version("$Revision: 4655 $");
 script_tag(name:"last_modification", value:"$Date: 2016-12-01 16:18:13 +0100 (Thu, 01 Dec 2016) $");
 script_tag(name:"creation_date", value:"2009-11-11 15:56:44 +0100 (Wed, 11 Nov 2009)");
 script_cve_id("CVE-2009-3298", "CVE-2009-3299");
 script_tag(name:"cvss_base", value:"6.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
 script_name("Debian Security Advisory DSA 1924-1 (mahara)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com");
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
if ((res = isdpkgvuln(pkg:"mahara-apache2", ver:"1.0.4-4+lenny4", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mahara", ver:"1.0.4-4+lenny4", rls:"DEB5.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
