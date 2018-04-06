# OpenVAS Vulnerability Test
# $Id: deb_2950.nasl 9354 2018-04-06 07:15:32Z cfischer $
# Auto-generated from advisory DSA 2950-1 using nvtgen 1.0
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

tag_affected  = "openssl on Debian Linux";
tag_insight   = "This package contains the openssl binary and related tools.";
tag_solution  = "For the stable distribution (wheezy), these problems have been fixed in
version 1.0.1e-2+deb7u10. All applications linked to openssl need to
be restarted. You can use the tool checkrestart from the package
debian-goodies to detect affected programs or reboot your system. There's
also a forthcoming security update for the Linux kernel later the day
(CVE-2014-3153 
), so you need to reboot anyway. Perfect timing, isn't it?

For the unstable distribution (sid), these problems will be fixed soon.

We recommend that you upgrade your openssl packages.";
tag_summary   = "Multiple vulnerabilities have been discovered in OpenSSL:

CVE-2014-0195 
Jueri Aedla discovered that a buffer overflow in processing DTLS
fragments could lead to the execution of arbitrary code or denial
of service.

CVE-2014-0221 
Imre Rad discovered the processing of DTLS hello packets is
susceptible to denial of service.

CVE-2014-0224 
KIKUCHI Masashi discovered that carefully crafted handshakes can
force the use of weak keys, resulting in potential man-in-the-middle
attacks.

CVE-2014-3470 
Felix Groebert and Ivan Fratric discovered that the implementation of
anonymous ECDH ciphersuites is suspectible to denial of service.

Additional information can be found at
http://www.openssl.org/news/secadv_20140605.txt";
tag_vuldetect = "This check tests the installed software version using the apt package manager.";

if(description)
{
    script_oid("1.3.6.1.4.1.25623.1.0.702950");
    script_version("$Revision: 9354 $");
    script_cve_id("CVE-2014-0195", "CVE-2014-0221", "CVE-2014-0224", "CVE-2014-3153", "CVE-2014-3470");
    script_name("Debian Security Advisory DSA 2950-1 (openssl - security update)");
    script_tag(name: "last_modification", value:"$Date: 2018-04-06 09:15:32 +0200 (Fri, 06 Apr 2018) $");
    script_tag(name: "creation_date", value:"2014-06-05 00:00:00 +0200 (Thu, 05 Jun 2014)");
    script_tag(name:"cvss_base", value:"7.2");
    script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

    script_xref(name: "URL", value: "http://www.debian.org/security/2014/dsa-2950.html");


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
if ((res = isdpkgvuln(pkg:"libssl-dev", ver:"1.0.1e-2+deb7u10", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libssl-doc", ver:"1.0.1e-2+deb7u10", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libssl1.0.0", ver:"1.0.1e-2+deb7u10", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libssl1.0.0-dbg", ver:"1.0.1e-2+deb7u10", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openssl", ver:"1.0.1e-2+deb7u10", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libssl-dev", ver:"1.0.1e-2+deb7u10", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libssl-doc", ver:"1.0.1e-2+deb7u10", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libssl1.0.0", ver:"1.0.1e-2+deb7u10", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libssl1.0.0-dbg", ver:"1.0.1e-2+deb7u10", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openssl", ver:"1.0.1e-2+deb7u10", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libssl-dev", ver:"1.0.1e-2+deb7u10", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libssl-doc", ver:"1.0.1e-2+deb7u10", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libssl1.0.0", ver:"1.0.1e-2+deb7u10", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libssl1.0.0-dbg", ver:"1.0.1e-2+deb7u10", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openssl", ver:"1.0.1e-2+deb7u10", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libssl-dev", ver:"1.0.1e-2+deb7u10", rls:"DEB7.3")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libssl-doc", ver:"1.0.1e-2+deb7u10", rls:"DEB7.3")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libssl1.0.0", ver:"1.0.1e-2+deb7u10", rls:"DEB7.3")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libssl1.0.0-dbg", ver:"1.0.1e-2+deb7u10", rls:"DEB7.3")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openssl", ver:"1.0.1e-2+deb7u10", rls:"DEB7.3")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
