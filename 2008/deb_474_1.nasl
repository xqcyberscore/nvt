# OpenVAS Vulnerability Test
# $Id: deb_474_1.nasl 3983 2016-09-07 05:46:06Z teissa $
# Description: Auto-generated from advisory DSA 474-1
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
tag_insight = "A vulnerability was discovered in squid, an Internet object cache,
whereby access control lists based on URLs could be bypassed
(CVE-2004-0189).  Two other bugs were also fixed with patches
squid-2.4.STABLE7-url_escape.patch (a buffer overrun which does not
appear to be exploitable) and squid-2.4.STABLE7-url_port.patch (a
potential denial of service).

For the stable distribution (woody) these problems have been fixed in
version 2.4.6-2woody2.

For the unstable distribution (sid) these problems have been fixed in
version 2.5.5-1.

We recommend that you update your squid package.";
tag_summary = "The remote host is missing an update to squid
announced via advisory DSA 474-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20474-1";

if(description)
{
 script_id(53172);
 script_version("$Revision: 3983 $");
 script_tag(name:"last_modification", value:"$Date: 2016-09-07 07:46:06 +0200 (Wed, 07 Sep 2016) $");
 script_tag(name:"creation_date", value:"2008-01-17 22:41:51 +0100 (Thu, 17 Jan 2008)");
 script_bugtraq_id(9778);
 script_cve_id("CVE-2004-0189");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("Debian Security Advisory DSA 474-1 (squid)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2005 E-Soft Inc. http://www.securityspace.com");
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
if ((res = isdpkgvuln(pkg:"squid", ver:"2.4.6-2woody2", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"squid-cgi", ver:"2.4.6-2woody2", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"squidclient", ver:"2.4.6-2woody2", rls:"DEB3.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
