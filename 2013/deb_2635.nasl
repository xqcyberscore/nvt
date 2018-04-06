# OpenVAS Vulnerability Test
# $Id: deb_2635.nasl 9353 2018-04-06 07:14:20Z cfischer $
# Auto-generated from advisory DSA 2635-1 using nvtgen 1.0
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

tag_affected  = "cfingerd on Debian Linux";
tag_insight   = "This is a free replacement for standard finger daemons such as GNU
fingerd and MIT fingerd. Cfingerd can enable/disable finger services
to individual users, rather than to all users on a given host. It is
able to respond to a finger request to a specified user by running a
shell script (e.g., finger doorbell@mysite.mydomain might cause a
sound file to be sent) rather than just a plain text file.";
tag_solution  = "For the stable distribution (squeeze), this problem has been fixed in
version 1.4.3-3+squeeze1.

For the testing distribution (wheezy), this problem has been fixed in
version 1.4.3-3.1.

For the unstable distribution (sid), this problem has been fixed in
version 1.4.3-3.1.

We recommend that you upgrade your cfingerd packages.";
tag_summary   = "Malcolm Scott discovered a remote-exploitable buffer overflow in the
RFC1413 (ident) client of cfingerd, a configurable finger daemon. This
vulnerability was introduced in a previously applied patch to the
cfingerd package in 1.4.3-3.";
tag_vuldetect = "This check tests the installed software version using the apt package manager.";

if(description)
{
    script_oid("1.3.6.1.4.1.25623.1.0.892635");
    script_version("$Revision: 9353 $");
    script_cve_id("CVE-2013-1049");
    script_name("Debian Security Advisory DSA 2635-1 (cfingerd - buffer overflow)");
    script_tag(name: "last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
    script_tag(name: "creation_date", value:"2013-03-01 00:00:00 +0100 (Fri, 01 Mar 2013)");
    script_tag(name: "cvss_base", value:"10.0");
    script_tag(name: "cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

    script_xref(name: "URL", value: "http://www.debian.org/security/2013/dsa-2635.html");


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
if ((res = isdpkgvuln(pkg:"cfingerd", ver:"1.4.3-3+squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"cfingerd", ver:"1.4.3-3.1", rls:"DEB7.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
