# OpenVAS Vulnerability Test
# $Id: deb_2878.nasl 9354 2018-04-06 07:15:32Z cfischer $
# Auto-generated from advisory DSA 2878-1 using nvtgen 1.0
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

tag_affected  = "virtualbox on Debian Linux";
tag_insight   = "VirtualBox is a free x86 virtualization solution allowing a wide range
of x86 operating systems such as Windows, DOS, BSD or Linux to run on a
Linux system.";
tag_solution  = "For the oldstable distribution (squeeze), these problems have been fixed in
version 3.2.10-dfsg-1+squeeze2 of the virtualbox-ose source package.

For the stable distribution (wheezy), these problems have been fixed in
version 4.1.18-dfsg-2+deb7u2.

For the testing distribution (jessie), these problems have been fixed in
version 4.3.6-dfsg-1.

For the unstable distribution (sid), these problems have been fixed in
version 4.3.6-dfsg-1.

We recommend that you upgrade your virtualbox packages.";
tag_summary   = "Matthew Daley discovered multiple vulnerabilities in VirtualBox, a x86
virtualisation solution, resulting in denial of service, privilege
escalation and an information leak.";
tag_vuldetect = "This check tests the installed software version using the apt package manager.";

if(description)
{
    script_oid("1.3.6.1.4.1.25623.1.0.702878");
    script_version("$Revision: 9354 $");
    script_cve_id("CVE-2013-5892", "CVE-2014-0404", "CVE-2014-0406", "CVE-2014-0407");
    script_name("Debian Security Advisory DSA 2878-1 (virtualbox - security update)");
    script_tag(name: "last_modification", value:"$Date: 2018-04-06 09:15:32 +0200 (Fri, 06 Apr 2018) $");
    script_tag(name: "creation_date", value:"2014-03-13 00:00:00 +0100 (Thu, 13 Mar 2014)");
    script_tag(name: "cvss_base", value:"3.5");
    script_tag(name: "cvss_base_vector", value:"AV:L/AC:H/Au:S/C:P/I:P/A:P");

    script_xref(name: "URL", value: "http://www.debian.org/security/2014/dsa-2878.html");


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
if ((res = isdpkgvuln(pkg:"virtualbox-ose", ver:"3.2.10-dfsg-1+squeeze2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"virtualbox-ose-dbg", ver:"3.2.10-dfsg-1+squeeze2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"virtualbox-ose-dkms", ver:"3.2.10-dfsg-1+squeeze2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"virtualbox-ose-fuse", ver:"3.2.10-dfsg-1+squeeze2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"virtualbox-ose-guest-dkms", ver:"3.2.10-dfsg-1+squeeze2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"virtualbox-ose-guest-source", ver:"3.2.10-dfsg-1+squeeze2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"virtualbox-ose-guest-utils", ver:"3.2.10-dfsg-1+squeeze2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"virtualbox-ose-guest-x11", ver:"3.2.10-dfsg-1+squeeze2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"virtualbox-ose-qt", ver:"3.2.10-dfsg-1+squeeze2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"virtualbox-ose-source", ver:"3.2.10-dfsg-1+squeeze2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"virtualbox", ver:"4.1.18-dfsg-2+deb7u2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"virtualbox-dbg", ver:"4.1.18-dfsg-2+deb7u2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"virtualbox-dkms", ver:"4.1.18-dfsg-2+deb7u2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"virtualbox-fuse", ver:"4.1.18-dfsg-2+deb7u2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"virtualbox-guest-dkms", ver:"4.1.18-dfsg-2+deb7u2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"virtualbox-guest-source", ver:"4.1.18-dfsg-2+deb7u2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"virtualbox-guest-utils", ver:"4.1.18-dfsg-2+deb7u2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"virtualbox-guest-x11", ver:"4.1.18-dfsg-2+deb7u2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"virtualbox-ose", ver:"4.1.18-dfsg-2+deb7u2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"virtualbox-ose-dbg", ver:"4.1.18-dfsg-2+deb7u2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"virtualbox-ose-dkms", ver:"4.1.18-dfsg-2+deb7u2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"virtualbox-ose-fuse", ver:"4.1.18-dfsg-2+deb7u2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"virtualbox-ose-guest-dkms", ver:"4.1.18-dfsg-2+deb7u2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"virtualbox-ose-guest-source", ver:"4.1.18-dfsg-2+deb7u2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"virtualbox-ose-guest-utils", ver:"4.1.18-dfsg-2+deb7u2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"virtualbox-ose-guest-x11", ver:"4.1.18-dfsg-2+deb7u2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"virtualbox-ose-qt", ver:"4.1.18-dfsg-2+deb7u2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"virtualbox-ose-source", ver:"4.1.18-dfsg-2+deb7u2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"virtualbox-qt", ver:"4.1.18-dfsg-2+deb7u2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"virtualbox-source", ver:"4.1.18-dfsg-2+deb7u2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"virtualbox", ver:"4.1.18-dfsg-2+deb7u2", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"virtualbox-dbg", ver:"4.1.18-dfsg-2+deb7u2", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"virtualbox-dkms", ver:"4.1.18-dfsg-2+deb7u2", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"virtualbox-fuse", ver:"4.1.18-dfsg-2+deb7u2", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"virtualbox-guest-dkms", ver:"4.1.18-dfsg-2+deb7u2", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"virtualbox-guest-source", ver:"4.1.18-dfsg-2+deb7u2", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"virtualbox-guest-utils", ver:"4.1.18-dfsg-2+deb7u2", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"virtualbox-guest-x11", ver:"4.1.18-dfsg-2+deb7u2", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"virtualbox-ose", ver:"4.1.18-dfsg-2+deb7u2", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"virtualbox-ose-dbg", ver:"4.1.18-dfsg-2+deb7u2", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"virtualbox-ose-dkms", ver:"4.1.18-dfsg-2+deb7u2", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"virtualbox-ose-fuse", ver:"4.1.18-dfsg-2+deb7u2", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"virtualbox-ose-guest-dkms", ver:"4.1.18-dfsg-2+deb7u2", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"virtualbox-ose-guest-source", ver:"4.1.18-dfsg-2+deb7u2", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"virtualbox-ose-guest-utils", ver:"4.1.18-dfsg-2+deb7u2", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"virtualbox-ose-guest-x11", ver:"4.1.18-dfsg-2+deb7u2", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"virtualbox-ose-qt", ver:"4.1.18-dfsg-2+deb7u2", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"virtualbox-ose-source", ver:"4.1.18-dfsg-2+deb7u2", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"virtualbox-qt", ver:"4.1.18-dfsg-2+deb7u2", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"virtualbox-source", ver:"4.1.18-dfsg-2+deb7u2", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"virtualbox", ver:"4.1.18-dfsg-2+deb7u2", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"virtualbox-dbg", ver:"4.1.18-dfsg-2+deb7u2", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"virtualbox-dkms", ver:"4.1.18-dfsg-2+deb7u2", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"virtualbox-fuse", ver:"4.1.18-dfsg-2+deb7u2", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"virtualbox-guest-dkms", ver:"4.1.18-dfsg-2+deb7u2", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"virtualbox-guest-source", ver:"4.1.18-dfsg-2+deb7u2", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"virtualbox-guest-utils", ver:"4.1.18-dfsg-2+deb7u2", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"virtualbox-guest-x11", ver:"4.1.18-dfsg-2+deb7u2", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"virtualbox-ose", ver:"4.1.18-dfsg-2+deb7u2", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"virtualbox-ose-dbg", ver:"4.1.18-dfsg-2+deb7u2", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"virtualbox-ose-dkms", ver:"4.1.18-dfsg-2+deb7u2", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"virtualbox-ose-fuse", ver:"4.1.18-dfsg-2+deb7u2", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"virtualbox-ose-guest-dkms", ver:"4.1.18-dfsg-2+deb7u2", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"virtualbox-ose-guest-source", ver:"4.1.18-dfsg-2+deb7u2", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"virtualbox-ose-guest-utils", ver:"4.1.18-dfsg-2+deb7u2", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"virtualbox-ose-guest-x11", ver:"4.1.18-dfsg-2+deb7u2", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"virtualbox-ose-qt", ver:"4.1.18-dfsg-2+deb7u2", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"virtualbox-ose-source", ver:"4.1.18-dfsg-2+deb7u2", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"virtualbox-qt", ver:"4.1.18-dfsg-2+deb7u2", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"virtualbox-source", ver:"4.1.18-dfsg-2+deb7u2", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"virtualbox", ver:"4.1.18-dfsg-2+deb7u2", rls:"DEB7.3")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"virtualbox-dbg", ver:"4.1.18-dfsg-2+deb7u2", rls:"DEB7.3")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"virtualbox-dkms", ver:"4.1.18-dfsg-2+deb7u2", rls:"DEB7.3")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"virtualbox-fuse", ver:"4.1.18-dfsg-2+deb7u2", rls:"DEB7.3")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"virtualbox-guest-dkms", ver:"4.1.18-dfsg-2+deb7u2", rls:"DEB7.3")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"virtualbox-guest-source", ver:"4.1.18-dfsg-2+deb7u2", rls:"DEB7.3")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"virtualbox-guest-utils", ver:"4.1.18-dfsg-2+deb7u2", rls:"DEB7.3")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"virtualbox-guest-x11", ver:"4.1.18-dfsg-2+deb7u2", rls:"DEB7.3")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"virtualbox-ose", ver:"4.1.18-dfsg-2+deb7u2", rls:"DEB7.3")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"virtualbox-ose-dbg", ver:"4.1.18-dfsg-2+deb7u2", rls:"DEB7.3")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"virtualbox-ose-dkms", ver:"4.1.18-dfsg-2+deb7u2", rls:"DEB7.3")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"virtualbox-ose-fuse", ver:"4.1.18-dfsg-2+deb7u2", rls:"DEB7.3")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"virtualbox-ose-guest-dkms", ver:"4.1.18-dfsg-2+deb7u2", rls:"DEB7.3")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"virtualbox-ose-guest-source", ver:"4.1.18-dfsg-2+deb7u2", rls:"DEB7.3")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"virtualbox-ose-guest-utils", ver:"4.1.18-dfsg-2+deb7u2", rls:"DEB7.3")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"virtualbox-ose-guest-x11", ver:"4.1.18-dfsg-2+deb7u2", rls:"DEB7.3")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"virtualbox-ose-qt", ver:"4.1.18-dfsg-2+deb7u2", rls:"DEB7.3")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"virtualbox-ose-source", ver:"4.1.18-dfsg-2+deb7u2", rls:"DEB7.3")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"virtualbox-qt", ver:"4.1.18-dfsg-2+deb7u2", rls:"DEB7.3")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"virtualbox-source", ver:"4.1.18-dfsg-2+deb7u2", rls:"DEB7.3")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
