# OpenVAS Vulnerability Test
# $Id: deb_2661.nasl 9353 2018-04-06 07:14:20Z cfischer $
# Auto-generated from advisory DSA 2661-1 using nvtgen 1.0
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

tag_affected  = "xorg-server on Debian Linux";
tag_insight   = "The Xorg X server is an X server for several architectures and operating
systems, which is derived from the XFree86 4.x series of X servers.";
tag_solution  = "For the stable distribution (squeeze), this problem has been fixed in
version 2:1.7.7-16.

For the testing distribution (wheezy), this problem has been fixed in
version 2:1.12.4-6.

For the unstable distribution (sid), this problem has been fixed in
version 2:1.12.4-6.

We recommend that you upgrade your xorg-server packages.";
tag_summary   = "David Airlie and Peter Hutterer of Red Hat discovered that xorg-server,
the X.Org X server was vulnerable to an information disclosure flaw
related to input handling and devices hotplug.

When an X server is running but not on front (for example because of a VT
switch), a newly plugged input device would still be recognized and
handled by the X server, which would actually transmit input events to
its clients on the background.

This could allow an attacker to recover some input events not intended
for the X clients, including sensitive information.";
tag_vuldetect = "This check tests the installed software version using the apt package manager.";

if(description)
{
    script_oid("1.3.6.1.4.1.25623.1.0.892661");
    script_version("$Revision: 9353 $");
    script_cve_id("CVE-2013-1940");
    script_name("Debian Security Advisory DSA 2661-1 (xorg-server - information disclosure)");
    script_tag(name: "last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
    script_tag(name: "creation_date", value:"2013-04-17 00:00:00 +0200 (Wed, 17 Apr 2013)");
    script_tag(name: "cvss_base", value:"2.1");
    script_tag(name: "cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");

    script_xref(name: "URL", value: "http://www.debian.org/security/2013/dsa-2661.html");


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
if ((res = isdpkgvuln(pkg:"xdmx", ver:"2:1.7.7-16", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xdmx-tools", ver:"2:1.7.7-16", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xnest", ver:"2:1.7.7-16", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xserver-common", ver:"2:1.7.7-16", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xserver-xephyr", ver:"2:1.7.7-16", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xserver-xfbdev", ver:"2:1.7.7-16", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xserver-xorg-core", ver:"2:1.7.7-16", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xserver-xorg-core-dbg", ver:"2:1.7.7-16", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xserver-xorg-dev", ver:"2:1.7.7-16", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xvfb", ver:"2:1.7.7-16", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xdmx", ver:"2:1.12.4-6", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xdmx-tools", ver:"2:1.12.4-6", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xnest", ver:"2:1.12.4-6", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xserver-common", ver:"2:1.12.4-6", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xserver-xephyr", ver:"2:1.12.4-6", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xserver-xfbdev", ver:"2:1.12.4-6", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xserver-xorg-core", ver:"2:1.12.4-6", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xserver-xorg-core-dbg", ver:"2:1.12.4-6", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xserver-xorg-dev", ver:"2:1.12.4-6", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xvfb", ver:"2:1.12.4-6", rls:"DEB7.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
