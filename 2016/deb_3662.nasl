# OpenVAS Vulnerability Test
# $Id: deb_3662.nasl 8168 2017-12-19 07:30:15Z teissa $
# Auto-generated from advisory DSA 3662-1 using nvtgen 1.0
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
    script_oid("1.3.6.1.4.1.25623.1.0.703662");
    script_version("$Revision: 8168 $");
    script_cve_id("CVE-2016-7142");
    script_name("Debian Security Advisory DSA 3662-1 (inspircd - security update)");
    script_tag(name: "last_modification", value: "$Date: 2017-12-19 08:30:15 +0100 (Tue, 19 Dec 2017) $");
    script_tag(name: "creation_date", value: "2016-09-08 00:00:00 +0200 (Thu, 08 Sep 2016)");
    script_tag(name:"cvss_base", value:"4.3");
    script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
    script_tag(name: "solution_type", value: "VendorFix");
    script_tag(name: "qod_type", value: "package");

    script_xref(name: "URL", value: "http://www.debian.org/security/2016/dsa-3662.html");


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
    script_tag(name: "solution",  value: "For the stable distribution (jessie), this problem has been fixed in
version 2.0.17-1+deb8u2.

For the unstable distribution (sid), this problem has been fixed in
version 2.0.23-1.

We recommend that you upgrade your inspircd packages.");
    script_tag(name: "summary",   value: "It was discovered that incorrect SASL authentication in the Inspircd
IRC server may lead to users impersonating other users.");
    script_tag(name: "vuldetect", value: "This check tests the installed software version using the apt package manager.");

    exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if ((res = isdpkgvuln(pkg:"inspircd", ver:"2.0.17-1+deb8u2", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"inspircd-dbg", ver:"2.0.17-1+deb8u2", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
