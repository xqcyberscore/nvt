# OpenVAS Vulnerability Test
# $Id: deb_2456_1.nasl 9353 2018-04-06 07:14:20Z cfischer $
# Auto-generated from advisory DSA 2456-1 using nvtgen 1.0
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

tag_affected  = "dropbear on Debian Linux";
tag_insight   = "dropbear is a SSH 2 server and client designed to be small enough to
be used in small memory environments, while still being functional and
secure enough for general use.";
tag_solution  = "For the stable distribution (squeeze), this problem has been fixed in
version 0.52-5+squeeze1.

For the testing distribution (wheezy), this problem has been fixed in
version 2012.55-1.

For the unstable distribution (sid), this problem has been fixed in
version 2012.55-1.

We recommend that you upgrade your dropbear packages.";
tag_summary   = "Danny Fullerton discovered a use-after-free in the Dropbear SSH daemon,
resulting in potential execution of arbitrary code. Exploitation is
limited to users, who have been authenticated through public key
authentication and for which command restrictions are in place.";
tag_vuldetect = "This check tests the installed software version using the apt package manager.";

if(description)
{
    script_oid("1.3.6.1.4.1.25623.1.0.892456");
    script_version("$Revision: 9353 $");
    script_cve_id("CVE-2012-0920");
    script_name("Debian Security Advisory DSA 2456-1 (dropbear - use after free)");
    script_tag(name: "last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
    script_tag(name:"creation_date", value:"2013-09-18 11:53:02 +0200 (Wed, 18 Sep 2013)");
    script_tag(name: "cvss_base", value:"7.1");
    script_tag(name: "cvss_base_vector", value:"AV:N/AC:H/Au:S/C:C/I:C/A:C");

    script_xref(name: "URL", value: "http://www.debian.org/security/2012/dsa-2456.html");


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
if ((res = isdpkgvuln(pkg:"dropbear", ver:"0.52-5+squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"dropbear", ver:"2012.55-1", rls:"DEB7.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
