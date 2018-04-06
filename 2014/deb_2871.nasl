# OpenVAS Vulnerability Test
# $Id: deb_2871.nasl 9354 2018-04-06 07:15:32Z cfischer $
# Auto-generated from advisory DSA 2871-1 using nvtgen 1.0
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

tag_affected  = "wireshark on Debian Linux";
tag_insight   = "Wireshark is a network 'sniffer' - a tool that captures and analyzes
packets off the wire. Wireshark can decode too many protocols to list
here.";
tag_solution  = "For the oldstable distribution (squeeze), these problems have been fixed in
version 1.2.11-6+squeeze14.

For the stable distribution (wheezy), these problems have been fixed in
version 1.8.2-5wheezy10.

For the unstable distribution (sid), these problems have been fixed in
version 1.10.6-1.

We recommend that you upgrade your wireshark packages.";
tag_summary   = "Multiple vulnerabilities were discovered in Wireshark:

CVE-2014-2281 
Moshe Kaplan discovered that the NFS dissector could be crashed,
resulting in denial of service.

CVE-2014-2283 
It was discovered that the RLC dissector could be crashed, resulting
in denial of service.

CVE-2014-2299 
Wesley Neelen discovered a buffer overflow in the MPEG file parser,
which could lead to the execution of arbitrary code.";
tag_vuldetect = "This check tests the installed software version using the apt package manager.";

if(description)
{
    script_oid("1.3.6.1.4.1.25623.1.0.702871");
    script_version("$Revision: 9354 $");
    script_cve_id("CVE-2014-2281", "CVE-2014-2283", "CVE-2014-2299");
    script_name("Debian Security Advisory DSA 2871-1 (wireshark - several vulnerabilities)");
    script_tag(name: "last_modification", value:"$Date: 2018-04-06 09:15:32 +0200 (Fri, 06 Apr 2018) $");
    script_tag(name: "creation_date", value:"2014-03-10 00:00:00 +0100 (Mon, 10 Mar 2014)");
    script_tag(name: "cvss_base", value:"9.3");
    script_tag(name: "cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

    script_xref(name: "URL", value: "http://www.debian.org/security/2014/dsa-2871.html");


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
if ((res = isdpkgvuln(pkg:"tshark", ver:"1.2.11-6+squeeze14", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"wireshark", ver:"1.2.11-6+squeeze14", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"wireshark-common", ver:"1.2.11-6+squeeze14", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"wireshark-dbg", ver:"1.2.11-6+squeeze14", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"wireshark-dev", ver:"1.2.11-6+squeeze14", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libwireshark-data", ver:"1.8.2-5wheezy10", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libwireshark-dev", ver:"1.8.2-5wheezy10", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libwireshark2", ver:"1.8.2-5wheezy10", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libwiretap-dev", ver:"1.8.2-5wheezy10", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libwiretap2", ver:"1.8.2-5wheezy10", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libwsutil-dev", ver:"1.8.2-5wheezy10", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libwsutil2", ver:"1.8.2-5wheezy10", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"tshark", ver:"1.8.2-5wheezy10", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"wireshark", ver:"1.8.2-5wheezy10", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"wireshark-common", ver:"1.8.2-5wheezy10", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"wireshark-dbg", ver:"1.8.2-5wheezy10", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"wireshark-dev", ver:"1.8.2-5wheezy10", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"wireshark-doc", ver:"1.8.2-5wheezy10", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libwireshark-data", ver:"1.8.2-5wheezy10", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libwireshark-dev", ver:"1.8.2-5wheezy10", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libwireshark2", ver:"1.8.2-5wheezy10", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libwiretap-dev", ver:"1.8.2-5wheezy10", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libwiretap2", ver:"1.8.2-5wheezy10", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libwsutil-dev", ver:"1.8.2-5wheezy10", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libwsutil2", ver:"1.8.2-5wheezy10", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"tshark", ver:"1.8.2-5wheezy10", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"wireshark", ver:"1.8.2-5wheezy10", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"wireshark-common", ver:"1.8.2-5wheezy10", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"wireshark-dbg", ver:"1.8.2-5wheezy10", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"wireshark-dev", ver:"1.8.2-5wheezy10", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"wireshark-doc", ver:"1.8.2-5wheezy10", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libwireshark-data", ver:"1.8.2-5wheezy10", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libwireshark-dev", ver:"1.8.2-5wheezy10", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libwireshark2", ver:"1.8.2-5wheezy10", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libwiretap-dev", ver:"1.8.2-5wheezy10", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libwiretap2", ver:"1.8.2-5wheezy10", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libwsutil-dev", ver:"1.8.2-5wheezy10", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libwsutil2", ver:"1.8.2-5wheezy10", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"tshark", ver:"1.8.2-5wheezy10", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"wireshark", ver:"1.8.2-5wheezy10", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"wireshark-common", ver:"1.8.2-5wheezy10", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"wireshark-dbg", ver:"1.8.2-5wheezy10", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"wireshark-dev", ver:"1.8.2-5wheezy10", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"wireshark-doc", ver:"1.8.2-5wheezy10", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libwireshark-data", ver:"1.8.2-5wheezy10", rls:"DEB7.3")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libwireshark-dev", ver:"1.8.2-5wheezy10", rls:"DEB7.3")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libwireshark2", ver:"1.8.2-5wheezy10", rls:"DEB7.3")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libwiretap-dev", ver:"1.8.2-5wheezy10", rls:"DEB7.3")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libwiretap2", ver:"1.8.2-5wheezy10", rls:"DEB7.3")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libwsutil-dev", ver:"1.8.2-5wheezy10", rls:"DEB7.3")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libwsutil2", ver:"1.8.2-5wheezy10", rls:"DEB7.3")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"tshark", ver:"1.8.2-5wheezy10", rls:"DEB7.3")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"wireshark", ver:"1.8.2-5wheezy10", rls:"DEB7.3")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"wireshark-common", ver:"1.8.2-5wheezy10", rls:"DEB7.3")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"wireshark-dbg", ver:"1.8.2-5wheezy10", rls:"DEB7.3")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"wireshark-dev", ver:"1.8.2-5wheezy10", rls:"DEB7.3")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"wireshark-doc", ver:"1.8.2-5wheezy10", rls:"DEB7.3")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
