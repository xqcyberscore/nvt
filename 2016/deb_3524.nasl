# OpenVAS Vulnerability Test
# $Id: deb_3524.nasl 8154 2017-12-18 07:30:14Z teissa $
# Auto-generated from advisory DSA 3524-1 using nvtgen 1.0
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
    script_oid("1.3.6.1.4.1.25623.1.0.703524");
    script_version("$Revision: 8154 $");
    script_cve_id("CVE-2015-5254");
    script_name("Debian Security Advisory DSA 3524-1 (activemq - security update)");
    script_tag(name: "last_modification", value: "$Date: 2017-12-18 08:30:14 +0100 (Mon, 18 Dec 2017) $");
    script_tag(name: "creation_date", value: "2016-03-20 00:00:00 +0100 (Sun, 20 Mar 2016)");
    script_tag(name:"cvss_base", value:"7.5");
    script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
    script_tag(name: "solution_type", value: "VendorFix");
    script_tag(name: "qod_type", value: "package");

    script_xref(name: "URL", value: "http://www.debian.org/security/2016/dsa-3524.html");


    script_category(ACT_GATHER_INFO);

    script_copyright("Copyright (c) 2016 Greenbone Networks GmbH http://greenbone.net");
    script_family("Debian Local Security Checks");
    script_dependencies("gather-package-list.nasl");
    script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages");
    script_tag(name: "affected",  value: "activemq on Debian Linux");
    script_tag(name: "insight",   value: "Apache ActiveMQ is a message broker built
around Java Message Service (JMS) API : allow sending messages between two or more
clients in a loosely coupled, reliable, and asynchronous way.");
    script_tag(name: "solution",  value: "For the oldstable distribution (wheezy),
this problem has been fixed in version 5.6.0+dfsg-1+deb7u2.

For the stable distribution (jessie), this problem has been fixed in
version 5.6.0+dfsg1-4+deb8u2.

For the testing distribution (stretch), this problem has been fixed
in version 5.13.2+dfsg-1.

For the unstable distribution (sid), this problem has been fixed in
version 5.13.2+dfsg-1.

We recommend that you upgrade your activemq packages.");
    script_tag(name: "summary",   value: "It was discovered that the ActiveMQ
 Java message broker performs unsafe
deserialisation. For additional information, please refer to the
upstream advisory at
http://activemq.apache.org/security-advisories.data/CVE-2015-5254-announcement.txt
.");
    script_tag(name: "vuldetect", value: "This check tests the installed software
version using the apt package manager.");
    exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if ((res = isdpkgvuln(pkg:"activemq", ver:"5.13.2+dfsg-1", rls_regex:"DEB9.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libactivemq-java", ver:"5.13.2+dfsg-1", rls_regex:"DEB9.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libactivemq-java-doc", ver:"5.13.2+dfsg-1", rls_regex:"DEB9.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"activemq", ver:"5.6.0+dfsg1-4+deb8u2", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libactivemq-java", ver:"5.6.0+dfsg1-4+deb8u2", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libactivemq-java-doc", ver:"5.6.0+dfsg1-4+deb8u2", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"activemq", ver:"5.6.0+dfsg-1+deb7u2", rls_regex:"DEB7.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libactivemq-java", ver:"5.6.0+dfsg-1+deb7u2", rls_regex:"DEB7.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libactivemq-java-doc", ver:"5.6.0+dfsg-1+deb7u2", rls_regex:"DEB7.[0-9]+")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
