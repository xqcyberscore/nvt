# OpenVAS Vulnerability Test
# $Id: deb_2792.nasl 9353 2018-04-06 07:14:20Z cfischer $
# Auto-generated from advisory DSA 2792-1 using nvtgen 1.0
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

tag_affected  = "wireshark on Debian Linux";
tag_insight   = "Wireshark is a network 'sniffer' - a tool that captures and analyzes
packets off the wire. Wireshark can decode too many protocols to list
here.";
tag_solution  = "For the stable distribution (wheezy), these problems have been fixed in
version 1.8.2-5wheezy7.

For the unstable distribution (sid), these problems have been fixed in
version 1.10.3-1.

We recommend that you upgrade your wireshark packages.";
tag_summary   = "Multiple vulnerabilities were discovered in the dissectors for IEEE
802.15.4, NBAP, SIP and TCP, which could result in denial of service.

The oldstable distribution (squeeze) is only affected by CVE-2013-6340 
.
This problem has been fixed in version 1.2.11-6+squeeze13.";
tag_vuldetect = "This check tests the installed software version using the apt package manager.";

if(description)
{
    script_oid("1.3.6.1.4.1.25623.1.0.892792");
    script_version("$Revision: 9353 $");
    script_cve_id("CVE-2013-6338", "CVE-2013-6337", "CVE-2013-6340", "CVE-2013-6336");
    script_name("Debian Security Advisory DSA 2792-1 (wireshark - several vulnerabilities)");
    script_tag(name: "last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
    script_tag(name: "creation_date", value:"2013-11-04 00:00:00 +0100 (Mon, 04 Nov 2013)");
    script_tag(name: "cvss_base", value:"4.3");
    script_tag(name: "cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");

    script_xref(name: "URL", value: "http://www.debian.org/security/2013/dsa-2792.html");


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
if ((res = isdpkgvuln(pkg:"libwireshark-data", ver:"1.8.2-5wheezy7", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libwireshark-dev", ver:"1.8.2-5wheezy7", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libwireshark2", ver:"1.8.2-5wheezy7", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libwiretap-dev", ver:"1.8.2-5wheezy7", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libwiretap2", ver:"1.8.2-5wheezy7", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libwsutil-dev", ver:"1.8.2-5wheezy7", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libwsutil2", ver:"1.8.2-5wheezy7", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"tshark", ver:"1.8.2-5wheezy7", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"wireshark", ver:"1.8.2-5wheezy7", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"wireshark-common", ver:"1.8.2-5wheezy7", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"wireshark-dbg", ver:"1.8.2-5wheezy7", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"wireshark-dev", ver:"1.8.2-5wheezy7", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"wireshark-doc", ver:"1.8.2-5wheezy7", rls:"DEB7.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
