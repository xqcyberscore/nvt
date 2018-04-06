# OpenVAS Vulnerability Test
# $Id: deb_2383_1.nasl 9352 2018-04-06 07:13:02Z cfischer $
# Description: Auto-generated from advisory DSA 2383-1 (super)
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
tag_insight = "Robert Luberda discovered a buffer overflow in the syslog logging code of
Super, a tool to execute scripts (or other commands) as if they were root.
The default Debian configuration is not affected.

For the oldstable distribution (lenny), this problem has been fixed in
version 3.30.0-2+lenny1. Due to a technical limitation in the Debian
archive scripts this update cannot be released synchronously with the
stable update. It will be available shortly.

For the stable distribution (squeeze), this problem has been fixed in
version 3.30.0-3+squeeze1.

For the unstable distribution (sid), this problem will be fixed soon.

We recommend that you upgrade your super packages.";
tag_summary = "The remote host is missing an update to super
announced via advisory DSA 2383-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202383-1";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.70702");
 script_tag(name:"cvss_base", value:"4.4");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
 script_cve_id("CVE-2011-2776");
 script_version("$Revision: 9352 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2012-02-11 03:26:53 -0500 (Sat, 11 Feb 2012)");
 script_name("Debian Security Advisory DSA 2383-1 (super)");


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
if((res = isdpkgvuln(pkg:"super", ver:"3.30.0-2+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"super", ver:"3.30.0-3+squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}

if(report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
