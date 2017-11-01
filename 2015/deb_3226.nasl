# OpenVAS Vulnerability Test
# $Id: deb_3226.nasl 7604 2017-11-01 06:48:12Z asteins $
# Auto-generated from advisory DSA 3226-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH http://greenbone.net
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
    script_id(703226);
    script_version("$Revision: 7604 $");
    script_cve_id("CVE-2012-1836", "CVE-2012-6696", "CVE-2012-6697", "CVE-2015-6674");
    script_name("Debian Security Advisory DSA 3226-1 (inspircd - security update)");
    script_tag(name: "check_type", value: "authenticated package test");
    script_tag(name: "last_modification", value: "$Date: 2017-11-01 07:48:12 +0100 (Wed, 01 Nov 2017) $");
    script_tag(name: "creation_date", value: "2015-04-15 00:00:00 +0200 (Wed, 15 Apr 2015)");
    script_tag(name:"cvss_base", value:"7.5");
    script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
    script_tag(name: "solution_type", value: "VendorFix");
    script_tag(name: "qod_type", value: "package");

    script_xref(name: "URL", value: "http://www.debian.org/security/2015/dsa-3226.html");

    script_summary("Debian Security Advisory DSA 3226-1 (inspircd - security update)");

    script_category(ACT_GATHER_INFO);

    script_copyright("Copyright (c) 2016 Greenbone Networks GmbH http://greenbone.net");
    script_family("Debian Local Security Checks");
    script_dependencies("gather-package-list.nasl");
    script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages");
    script_tag(name: "affected",  value: "inspircd on Debian Linux");
        script_tag(name: "insight",   value: "InspIRCd is a modular C++ IRC Daemon for several operating systems created
to provide a stable, modern, lightweight irc server from scratch and provide
a vast number of features in a modularised form using an advanced module API.
By keeping the functionality of the main core to a minimum, the server is very
stable, fast and customizable.");
    script_tag(name: "solution",  value: "For the stable distribution (wheezy), this problem has been fixed in
version 2.0.5-1+deb7u1.

For the upcoming stable distribution (jessie) and unstable
distribution (sid), this problem has been fixed in version 2.0.16-1.

We recommend that you upgrade your inspircd packages.");
    script_tag(name: "summary",   value: "Adam discovered several problems in inspircd, an IRC daemon:

An incomplete patch for CVE-2012-1836 

failed to adequately resolve the problem where maliciously crafted DNS
requests could lead to remote code execution through a heap-based buffer
overflow.

The incorrect processing of specific DNS packets could trigger an
infinite loop, thus resulting in a denial of service.");
    script_tag(name: "vuldetect", value: "This check tests the installed software version using the apt package manager.");

    exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if ((res = isdpkgvuln(pkg:"inspircd", ver:"2.0.5-1+deb7u1", rls_regex:"DEB7.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"inspircd-dbg", ver:"2.0.5-1+deb7u1", rls_regex:"DEB7.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"inspircd", ver:"2.0.16-1", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"inspircd-dbg", ver:"2.0.16-1", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
