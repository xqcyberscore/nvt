###########################################################################
# OpenVAS Vulnerability Test
# $Id: deb_3079.nasl 9354 2018-04-06 07:15:32Z cfischer $
# Auto-generated from advisory DSA 3079-1 using nvtgen 1.0
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
#############################################################################

if(description)
{
    script_oid("1.3.6.1.4.1.25623.1.0.703079");
    script_version("$Revision: 9354 $");
    script_cve_id("CVE-2014-3158");
    script_name("Debian Security Advisory DSA 3079-1 (ppp - security update)");
    script_tag(name: "last_modification", value: "$Date: 2018-04-06 09:15:32 +0200 (Fri, 06 Apr 2018) $");
    script_tag(name: "creation_date", value: "2014-11-28 00:00:00 +0100 (Fri, 28 Nov 2014)");
    script_tag(name:"cvss_base", value:"7.5");
    script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

    script_xref(name: "URL", value: "http://www.debian.org/security/2014/dsa-3079.html");


    script_category(ACT_GATHER_INFO);

    script_copyright("Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net");
    script_family("Debian Local Security Checks");
    script_dependencies("gather-package-list.nasl");
    script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages");
    script_tag(name: "affected",  value: "ppp on Debian Linux");
    script_tag(name: "insight",   value: "The Point-to-Point Protocol provides
a standard way to transmit datagrams over a serial link, as well as a standard way
for the machines at either end of the link to negotiate various optional
characteristics of the link.");
    script_tag(name: "solution",  value: "For the stable distribution (wheezy), this
problem has been fixed in version 2.4.5-5.1+deb7u1.

For the upcoming stable distribution (jessie) and unstable
distribution (sid), this problem has been fixed in version 2.4.6-3.

We recommend that you upgrade your ppp packages.");
    script_tag(name: "summary",   value: "A vulnerability was discovered in ppp,
an implementation of the Point-to-Point Protocol: an integer overflow in the routine
responsible for parsing user-supplied options potentially allows a local attacker
to gain root privileges.");
    script_tag(name: "vuldetect", value: "This check tests the installed software
version using the apt package manager.");
    script_tag(name:"qod_type", value:"package");
    script_tag(name:"solution_type", value:"VendorFix");
    exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if ((res = isdpkgvuln(pkg:"ppp", ver:"2.4.5-5.1+deb7u1", rls_regex:"DEB7.[0-9]")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ppp-dev", ver:"2.4.5-5.1+deb7u1", rls_regex:"DEB7.[0-9]")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
