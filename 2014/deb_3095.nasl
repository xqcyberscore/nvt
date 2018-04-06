# OpenVAS Vulnerability Test
# $Id: deb_3095.nasl 9354 2018-04-06 07:15:32Z cfischer $
# Auto-generated from advisory DSA 3095-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net
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


if(description)
{
    script_oid("1.3.6.1.4.1.25623.1.0.703095");
    script_version("$Revision: 9354 $");
    script_cve_id("CVE-2014-8091", "CVE-2014-8092", "CVE-2014-8093", "CVE-2014-8094",
                  "CVE-2014-8095", "CVE-2014-8096", "CVE-2014-8097", "CVE-2014-8098",
                  "CVE-2014-8099", "CVE-2014-8100", "CVE-2014-8101", "CVE-2014-8102");
    script_name("Debian Security Advisory DSA 3095-1 (xorg-server - security update)");
    script_tag(name: "last_modification", value: "$Date: 2018-04-06 09:15:32 +0200 (Fri, 06 Apr 2018) $");
    script_tag(name: "creation_date", value: "2014-12-10 00:00:00 +0100 (Wed, 10 Dec 2014)");
    script_tag(name:"cvss_base", value:"6.5");
    script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
    script_tag(name: "solution_type", value: "VendorFix");

    script_xref(name: "URL", value: "http://www.debian.org/security/2014/dsa-3095.html");


    script_category(ACT_GATHER_INFO);

    script_copyright("Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net");
    script_family("Debian Local Security Checks");
    script_dependencies("gather-package-list.nasl");
    script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages");
    script_tag(name: "affected",  value: "xorg-server on Debian Linux");
        script_tag(name: "insight",   value: "The Xorg X server is an X server
for several architectures and operating systems, which is derived from the XFree86
4.x series of X servers.");
    script_tag(name: "solution",  value: "For the stable distribution (wheezy),
these problems have been fixed in version 1.12.4-6+deb7u5.

For the upcoming stable distribution (jessie), these problems will be
fixed soon.

For the unstable distribution (sid), these problems have been fixed in
version 2:1.16.2.901-1.

We recommend that you upgrade your xorg-server packages.");
    script_tag(name: "summary",   value: "Ilja van Sprundel of IOActive discovered
several security issues in the X.org X server, which may lead to privilege
escalation or denial of service.");
    script_tag(name: "vuldetect", value: "This check tests the installed software
version using the apt package manager.");
    script_tag(name:"qod_type", value:"package");
    exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if ((res = isdpkgvuln(pkg:"xdmx", ver:"1.12.4-6+deb7u5", rls_regex:"DEB7.[0-9]")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xdmx-tools", ver:"1.12.4-6+deb7u5", rls_regex:"DEB7.[0-9]")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xnest", ver:"1.12.4-6+deb7u5", rls_regex:"DEB7.[0-9]")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xserver-common", ver:"1.12.4-6+deb7u5", rls_regex:"DEB7.[0-9]")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xserver-xephyr", ver:"1.12.4-6+deb7u5", rls_regex:"DEB7.[0-9]")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xserver-xfbdev", ver:"1.12.4-6+deb7u5", rls_regex:"DEB7.[0-9]")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xserver-xorg-core", ver:"1.12.4-6+deb7u5", rls_regex:"DEB7.[0-9]")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xserver-xorg-core-dbg", ver:"1.12.4-6+deb7u5", rls_regex:"DEB7.[0-9]")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xserver-xorg-dev", ver:"1.12.4-6+deb7u5", rls_regex:"DEB7.[0-9]")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xvfb", ver:"1.12.4-6+deb7u5", rls_regex:"DEB7.[0-9]")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
