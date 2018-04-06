# OpenVAS Vulnerability Test
# $Id: deb_2722.nasl 9353 2018-04-06 07:14:20Z cfischer $
# Auto-generated from advisory DSA 2722-1 using nvtgen 1.0
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

tag_affected  = "openjdk-7 on Debian Linux";
tag_insight   = "OpenJDK is a development environment for building applications,
applets, and components using the Java programming language.";
tag_solution  = "For the stable distribution (wheezy), these problems have been fixed in
version 7u25-2.3.10-1~deb7u1. In addition icedtea-web needed to be
updated to 1.4-3~deb7u1.

For the unstable distribution (sid), these problems have been fixed in
version 7u25-2.3.10-1.

We recommend that you upgrade your openjdk-7 packages.";
tag_summary   = "Several vulnerabilities have been discovered in OpenJDK, an
implementation of the Oracle Java platform, resulting in the execution
of arbitrary code, breakouts of the Java sandbox, information disclosure
or denial of service.";
tag_vuldetect = "This check tests the installed software version using the apt package manager.";

if(description)
{
    script_oid("1.3.6.1.4.1.25623.1.0.892722");
    script_version("$Revision: 9353 $");
    script_cve_id("CVE-2013-2470", "CVE-2013-2459", "CVE-2013-2454", "CVE-2013-2463", "CVE-2013-1500", "CVE-2013-2451", "CVE-2013-2445", "CVE-2013-1571", "CVE-2013-2450", "CVE-2013-2446", "CVE-2013-2460", "CVE-2013-2472", "CVE-2013-2471", "CVE-2013-2448", "CVE-2013-2444", "CVE-2013-2447", "CVE-2013-2473", "CVE-2013-2443", "CVE-2013-2452", "CVE-2013-2469", "CVE-2013-2461", "CVE-2013-2458", "CVE-2013-2455", "CVE-2013-2412", "CVE-2013-2449", "CVE-2013-2456", "CVE-2013-2465", "CVE-2013-2407", "CVE-2013-2457", "CVE-2013-2453");
    script_name("Debian Security Advisory DSA 2722-1 (openjdk-7 - several vulnerabilities)");
    script_tag(name: "last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
    script_tag(name: "creation_date", value:"2013-07-15 00:00:00 +0200 (Mon, 15 Jul 2013)");
    script_tag(name: "cvss_base", value:"10.0");
    script_tag(name: "cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

    script_xref(name: "URL", value: "http://www.debian.org/security/2013/dsa-2722.html");


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
if ((res = isdpkgvuln(pkg:"icedtea-7-jre-jamvm", ver:"7u25-2.3.10-1~deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openjdk-7-dbg", ver:"7u25-2.3.10-1~deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openjdk-7-demo", ver:"7u25-2.3.10-1~deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openjdk-7-doc", ver:"7u25-2.3.10-1~deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openjdk-7-jdk", ver:"7u25-2.3.10-1~deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openjdk-7-jre", ver:"7u25-2.3.10-1~deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openjdk-7-jre-headless", ver:"7u25-2.3.10-1~deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openjdk-7-jre-lib", ver:"7u25-2.3.10-1~deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openjdk-7-jre-zero", ver:"7u25-2.3.10-1~deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openjdk-7-source", ver:"7u25-2.3.10-1~deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
