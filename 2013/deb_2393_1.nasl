# OpenVAS Vulnerability Test
# $Id: deb_2393_1.nasl 9353 2018-04-06 07:14:20Z cfischer $
# Auto-generated from advisory DSA 2393-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH http://greenbone.net
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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

tag_affected  = "bip on Debian Linux";
tag_insight   = "Bip is a IRC proxy that supports replaying logged conversation when a client
connects, multiple clients on one irc server connection, It has a handy
logging directory structure. It is multiuser, and has a flexible
configuration. Some of its configuration can be changed at runtime with
special irc commands.";
tag_solution  = "For the stable distribution (squeeze), this problem has been fixed in
version 0.8.2-1squeeze4.

For the testing distribution (wheezy) and the unstable distribution (sid),
this problem will be fixed soon.

We recommend that you upgrade your bip packages.";
tag_summary   = "Julien Tinnes reported a buffer overflow in the Bip multiuser IRC proxy
which may allow arbitrary code execution by remote users.

The oldstable distribution (lenny) is not affected by this problem.";
tag_vuldetect = "This check tests the installed software version using the apt package manager.";

if(description)
{
    script_oid("1.3.6.1.4.1.25623.1.0.892393");
    script_version("$Revision: 9353 $");
    script_cve_id("CVE-2012-0806");
    script_name("Debian Security Advisory DSA 2393-1 (bip - buffer overflow)");
    script_tag(name: "last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
    script_tag(name:"creation_date", value:"2013-09-18 11:53:02 +0200 (Wed, 18 Sep 2013)");
    script_tag(name: "cvss_base", value:"6.5");
    script_tag(name: "cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

    script_xref(name: "URL", value: "http://www.debian.org/security/2012/dsa-2393.html");


    script_category(ACT_GATHER_INFO);

    script_copyright("Copyright (c) 2013 Greenbone Networks GmbH http://greenbone.net");
    script_family("Debian Local Security Checks");
    script_dependencies("gather-package-list.nasl");
    script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages");
    script_tag(name: "affected",  value: tag_affected);
    script_tag(name: "insight",   value: tag_insight);
#    script_tag(name: "impact",    value: tag_impact);
    script_tag(name: "solution",  value: tag_solution);
    script_tag(name: "summary",   value: tag_summary);
    script_tag(name: "vuldetect", value: tag_vuldetect);
    script_tag(name:"qod_type", value:"package");
    script_tag(name:"solution_type", value:"VendorFix");

    exit(0);
}

include("pkg-lib-deb.inc");

res = "";
report = "";
if ((res = isdpkgvuln(pkg:"bip", ver:"0.8.2-1squeeze4", rls:"DEB6.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
