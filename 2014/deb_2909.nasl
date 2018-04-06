# OpenVAS Vulnerability Test
# $Id: deb_2909.nasl 9354 2018-04-06 07:15:32Z cfischer $
# Auto-generated from advisory DSA 2909-1 using nvtgen 1.0
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

tag_affected  = "qemu on Debian Linux";
tag_insight   = "QEMU is a fast processor emulator: currently the package supports
ARM, CRIS, i386, M68k (ColdFire), MicroBlaze, MIPS, PowerPC, SH4,
SPARC and x86-64 emulation. By using dynamic translation it achieves
reasonable speed while being easy to port on new host CPUs. QEMU has
two operating modes:";
tag_solution  = "For the oldstable distribution (squeeze), this problem has been fixed in
version 0.12.5+dfsg-3squeeze4.

For the stable distribution (wheezy), this problem has been fixed in
version 1.1.2+dfsg-6a+deb7u1.

For the testing distribution (jessie), this problem has been fixed in
version 1.7.0+dfsg-8.

For the unstable distribution (sid), this problem has been fixed in
version 1.7.0+dfsg-8.

We recommend that you upgrade your qemu packages.";
tag_summary   = "Michael S. Tsirkin of Red Hat discovered a buffer overflow flaw in the
way qemu processed MAC addresses table update requests from the guest.

A privileged guest user could use this flaw to corrupt qemu process
memory on the host, which could potentially result in arbitrary code
execution on the host with the privileges of the qemu process.";
tag_vuldetect = "This check tests the installed software version using the apt package manager.";

if(description)
{
    script_oid("1.3.6.1.4.1.25623.1.0.702909");
    script_version("$Revision: 9354 $");
    script_cve_id("CVE-2014-0150");
    script_name("Debian Security Advisory DSA 2909-1 (qemu - security update)");
    script_tag(name: "last_modification", value:"$Date: 2018-04-06 09:15:32 +0200 (Fri, 06 Apr 2018) $");
    script_tag(name: "creation_date", value:"2014-04-18 00:00:00 +0200 (Fri, 18 Apr 2014)");
    script_tag(name:"cvss_base", value:"4.9");
    script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:S/C:P/I:P/A:P");

    script_xref(name: "URL", value: "http://www.debian.org/security/2014/dsa-2909.html");


    script_category(ACT_GATHER_INFO);

    script_copyright("Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net");
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

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if ((res = isdpkgvuln(pkg:"libqemu-dev", ver:"0.12.5+dfsg-3squeeze4", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"qemu", ver:"0.12.5+dfsg-3squeeze4", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"qemu-keymaps", ver:"0.12.5+dfsg-3squeeze4", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"qemu-system", ver:"0.12.5+dfsg-3squeeze4", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"qemu-user", ver:"0.12.5+dfsg-3squeeze4", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"qemu-user-static", ver:"0.12.5+dfsg-3squeeze4", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"qemu-utils", ver:"0.12.5+dfsg-3squeeze4", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"qemu", ver:"1.1.2+dfsg-6a+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"qemu-keymaps", ver:"1.1.2+dfsg-6a+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"qemu-system", ver:"1.1.2+dfsg-6a+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"qemu-user", ver:"1.1.2+dfsg-6a+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"qemu-user-static", ver:"1.1.2+dfsg-6a+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"qemu-utils", ver:"1.1.2+dfsg-6a+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"qemu", ver:"1.1.2+dfsg-6a+deb7u1", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"qemu-keymaps", ver:"1.1.2+dfsg-6a+deb7u1", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"qemu-system", ver:"1.1.2+dfsg-6a+deb7u1", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"qemu-user", ver:"1.1.2+dfsg-6a+deb7u1", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"qemu-user-static", ver:"1.1.2+dfsg-6a+deb7u1", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"qemu-utils", ver:"1.1.2+dfsg-6a+deb7u1", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"qemu", ver:"1.1.2+dfsg-6a+deb7u1", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"qemu-keymaps", ver:"1.1.2+dfsg-6a+deb7u1", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"qemu-system", ver:"1.1.2+dfsg-6a+deb7u1", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"qemu-user", ver:"1.1.2+dfsg-6a+deb7u1", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"qemu-user-static", ver:"1.1.2+dfsg-6a+deb7u1", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"qemu-utils", ver:"1.1.2+dfsg-6a+deb7u1", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"qemu", ver:"1.1.2+dfsg-6a+deb7u1", rls:"DEB7.3")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"qemu-keymaps", ver:"1.1.2+dfsg-6a+deb7u1", rls:"DEB7.3")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"qemu-system", ver:"1.1.2+dfsg-6a+deb7u1", rls:"DEB7.3")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"qemu-user", ver:"1.1.2+dfsg-6a+deb7u1", rls:"DEB7.3")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"qemu-user-static", ver:"1.1.2+dfsg-6a+deb7u1", rls:"DEB7.3")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"qemu-utils", ver:"1.1.2+dfsg-6a+deb7u1", rls:"DEB7.3")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
