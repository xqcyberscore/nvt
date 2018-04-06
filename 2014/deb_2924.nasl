# OpenVAS Vulnerability Test
# $Id: deb_2924.nasl 9354 2018-04-06 07:15:32Z cfischer $
# Auto-generated from advisory DSA 2924-1 using nvtgen 1.0
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

tag_affected  = "icedove on Debian Linux";
tag_insight   = "Icedove is an unbranded Thunderbird mail client suitable for free
distribution. It supports different mail accounts (POP, IMAP, Gmail), has an
integrated learning Spam filter, and offers easy organization of mails with
tagging and virtual folders. Also, more features can be added by installing
extensions.";
tag_solution  = "For the stable distribution (wheezy), these problems have been fixed in
version 24.5.0-1~deb7u1.

For the testing distribution (jessie), these problems have been fixed in
version 24.5.0-1.

For the unstable distribution (sid), these problems have been fixed in
version 24.5.0-1.

We recommend that you upgrade your icedove packages.";
tag_summary   = "Multiple security issues have been found in Icedove, Debian's version
of the Mozilla Thunderbird mail and news client: multiple memory safety
errors, buffer overflows, missing permission checks, out of bound reads,
use-after-frees and other implementation errors may lead to the
execution of arbitrary code, privilege escalation, cross-site scripting
or denial of service.";
tag_vuldetect = "This check tests the installed software version using the apt package manager.";

if(description)
{
    script_oid("1.3.6.1.4.1.25623.1.0.702924");
    script_version("$Revision: 9354 $");
    script_cve_id("CVE-2014-1518", "CVE-2014-1523", "CVE-2014-1524", "CVE-2014-1529", "CVE-2014-1530", "CVE-2014-1531", "CVE-2014-1532");
    script_name("Debian Security Advisory DSA 2924-1 (icedove - security update)");
    script_tag(name: "last_modification", value:"$Date: 2018-04-06 09:15:32 +0200 (Fri, 06 Apr 2018) $");
    script_tag(name: "creation_date", value:"2014-05-05 00:00:00 +0200 (Mon, 05 May 2014)");
    script_tag(name: "cvss_base", value:"10.0");
    script_tag(name: "cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

    script_xref(name: "URL", value: "http://www.debian.org/security/2014/dsa-2924.html");


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
if ((res = isdpkgvuln(pkg:"calendar-google-provider", ver:"24.5.0-1~deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"calendar-timezones", ver:"24.5.0-1~deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"icedove", ver:"24.5.0-1~deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"icedove-dbg", ver:"24.5.0-1~deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"icedove-dev", ver:"24.5.0-1~deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"iceowl-extension", ver:"24.5.0-1~deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"calendar-google-provider", ver:"24.5.0-1~deb7u1", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"calendar-timezones", ver:"24.5.0-1~deb7u1", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"icedove", ver:"24.5.0-1~deb7u1", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"icedove-dbg", ver:"24.5.0-1~deb7u1", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"icedove-dev", ver:"24.5.0-1~deb7u1", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"iceowl-extension", ver:"24.5.0-1~deb7u1", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"calendar-google-provider", ver:"24.5.0-1~deb7u1", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"calendar-timezones", ver:"24.5.0-1~deb7u1", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"icedove", ver:"24.5.0-1~deb7u1", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"icedove-dbg", ver:"24.5.0-1~deb7u1", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"icedove-dev", ver:"24.5.0-1~deb7u1", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"iceowl-extension", ver:"24.5.0-1~deb7u1", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"calendar-google-provider", ver:"24.5.0-1~deb7u1", rls:"DEB7.3")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"calendar-timezones", ver:"24.5.0-1~deb7u1", rls:"DEB7.3")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"icedove", ver:"24.5.0-1~deb7u1", rls:"DEB7.3")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"icedove-dbg", ver:"24.5.0-1~deb7u1", rls:"DEB7.3")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"icedove-dev", ver:"24.5.0-1~deb7u1", rls:"DEB7.3")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"iceowl-extension", ver:"24.5.0-1~deb7u1", rls:"DEB7.3")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
