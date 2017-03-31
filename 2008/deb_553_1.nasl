# OpenVAS Vulnerability Test
# $Id: deb_553_1.nasl 4004 2016-09-08 05:36:24Z teissa $
# Description: Auto-generated from advisory DSA 553-1
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
tag_insight = "A security problem has been discovered in getmail, a POP3 and APOP
mail gatherer and forwarder.  An attacker with a shell account on the
victims host could utilise getmail to overwrite arbitrary files when
it is running as root.

For the stable distribution (woody) this problem has been fixed in
version 2.3.7-2.

For the unstable distribution (sid) this problem has been fixed in
version 3.2.5-1.

We recommend that you upgrade your getmail package.";
tag_summary = "The remote host is missing an update to getmail
announced via advisory DSA 553-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20553-1";

if(description)
{
 script_id(53244);
 script_version("$Revision: 4004 $");
 script_tag(name:"last_modification", value:"$Date: 2016-09-08 07:36:24 +0200 (Thu, 08 Sep 2016) $");
 script_tag(name:"creation_date", value:"2008-01-17 22:45:44 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2004-0880", "CVE-2004-0881");
 script_tag(name:"cvss_base", value:"2.1");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:P/A:N");
 script_name("Debian Security Advisory DSA 553-1 (getmail)");



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
if ((res = isdpkgvuln(pkg:"getmail", ver:"2.3.7-2", rls:"DEB3.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
