# OpenVAS Vulnerability Test
# $Id: deb_2749.nasl 9353 2018-04-06 07:14:20Z cfischer $
# Auto-generated from advisory DSA 2749-1 using nvtgen 1.0
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

tag_affected  = "asterisk on Debian Linux";
tag_insight   = "Asterisk is an Open Source PBX and telephony toolkit. It is, in a
sense, middleware between Internet and telephony channels on the bottom,
and Internet and telephony applications at the top.";
tag_solution  = "For the oldstable distribution (squeeze), these problems have been fixed in
version 1:1.6.2.9-2+squeeze11.

For the stable distribution (wheezy), these problems have been fixed in
version 1.8.13.1~dfsg-3+deb7u1.

For the unstable distribution (sid), these problems will be fixed soon.

We recommend that you upgrade your asterisk packages.";
tag_summary   = "Colin Cuthbertson and Walter Doekes discovered two vulnerabilities in
the SIP processing code of Asterisk - an open source PBX and telephony
toolkit -, which could result in denial of service.";
tag_vuldetect = "This check tests the installed software version using the apt package manager.";

if(description)
{
    script_oid("1.3.6.1.4.1.25623.1.0.892749");
    script_version("$Revision: 9353 $");
    script_cve_id("CVE-2013-5642", "CVE-2013-5641");
    script_name("Debian Security Advisory DSA 2749-1 (asterisk - several vulnerabilities)");
    script_tag(name: "last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
    script_tag(name: "creation_date", value:"2013-09-02 00:00:00 +0200 (Mon, 02 Sep 2013)");
    script_tag(name: "cvss_base", value:"5.0");
    script_tag(name: "cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

    script_xref(name: "URL", value: "http://www.debian.org/security/2013/dsa-2749.html");


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
if ((res = isdpkgvuln(pkg:"asterisk", ver:"1:1.6.2.9-2+squeeze11", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"asterisk-config", ver:"1:1.6.2.9-2+squeeze11", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"asterisk-dbg", ver:"1:1.6.2.9-2+squeeze11", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"asterisk-dev", ver:"1:1.6.2.9-2+squeeze11", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"asterisk-doc", ver:"1:1.6.2.9-2+squeeze11", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"asterisk-h323", ver:"1:1.6.2.9-2+squeeze11", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"asterisk-sounds-main", ver:"1:1.6.2.9-2+squeeze11", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"asterisk", ver:"1.8.13.1~dfsg-3+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"asterisk-config", ver:"1.8.13.1~dfsg-3+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"asterisk-dahdi", ver:"1.8.13.1~dfsg-3+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"asterisk-dbg", ver:"1.8.13.1~dfsg-3+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"asterisk-dev", ver:"1.8.13.1~dfsg-3+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"asterisk-doc", ver:"1.8.13.1~dfsg-3+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"asterisk-mobile", ver:"1.8.13.1~dfsg-3+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"asterisk-modules", ver:"1.8.13.1~dfsg-3+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"asterisk-mp3", ver:"1.8.13.1~dfsg-3+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"asterisk-mysql", ver:"1.8.13.1~dfsg-3+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"asterisk-ooh323", ver:"1.8.13.1~dfsg-3+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"asterisk-voicemail", ver:"1.8.13.1~dfsg-3+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"asterisk-voicemail-imapstorage", ver:"1.8.13.1~dfsg-3+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"asterisk-voicemail-odbcstorage", ver:"1.8.13.1~dfsg-3+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
