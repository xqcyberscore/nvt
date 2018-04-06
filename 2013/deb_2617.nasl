# OpenVAS Vulnerability Test
# $Id: deb_2617.nasl 9353 2018-04-06 07:14:20Z cfischer $
# Auto-generated from advisory DSA 2617-1 using nvtgen 1.0
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

tag_affected  = "samba on Debian Linux";
tag_insight   = "Samba is an implementation of the SMB/CIFS protocol for Unix systems,
providing support for cross-platform file and printer sharing with
Microsoft Windows, OS X, and other Unix systems. Samba can also function
as an NT4-style domain controller, and can integrate with both NT4 domains
and Active Directory realms as a member server.";
tag_solution  = "For the stable distribution (squeeze), these problems have been fixed in
version 2:3.5.6~dfsg-3squeeze9.

For the testing distribution (wheezy), these problems have been fixed in
version 2:3.6.6-5.

For the unstable distribution (sid), these problems have been fixed in
version 2:3.6.6-5.

We recommend that you upgrade your samba packages.";
tag_summary   = "Jann Horn had reported two vulnerabilities in Samba, a popular
cross-platform network file and printer sharing suite. In particular,
these vulnerabilities affect to SWAT, the Samba Web Administration Tool.

CVE-2013-0213:
Clickjacking issue in SWAT

An attacker can integrate a SWAT page into a malicious web page via a
frame or iframe and then overlaid by other content. If an
authenticated valid user interacts with this malicious web page, she
might perform unintended changes in the Samba settings.

CVE-2013-0214:
Potential Cross-site request forgery

An attacker can persuade a valid SWAT user, who is logged in as root,
to click in a malicious link and trigger arbitrary unintended changes
in the Samba settings. In order to be vulnerable, the attacker needs
to know the victim's password.";
tag_vuldetect = "This check tests the installed software version using the apt package manager.";

if(description)
{
    script_oid("1.3.6.1.4.1.25623.1.0.892617");
    script_version("$Revision: 9353 $");
    script_cve_id("CVE-2013-0214", "CVE-2013-0213");
    script_name("Debian Security Advisory DSA 2617-1 (samba - several issues)");
    script_tag(name: "last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
    script_tag(name: "creation_date", value:"2013-02-02 00:00:00 +0100 (Sat, 02 Feb 2013)");
    script_tag(name: "cvss_base", value:"5.1");
    script_tag(name: "cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");

    script_xref(name: "URL", value: "http://www.debian.org/security/2013/dsa-2617.html");


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
if ((res = isdpkgvuln(pkg:"libpam-smbpass", ver:"2:3.5.6~dfsg-3squeeze9", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsmbclient", ver:"2:3.5.6~dfsg-3squeeze9", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsmbclient-dev", ver:"2:3.5.6~dfsg-3squeeze9", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libwbclient0", ver:"2:3.5.6~dfsg-3squeeze9", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"samba", ver:"2:3.5.6~dfsg-3squeeze9", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"samba-common", ver:"2:3.5.6~dfsg-3squeeze9", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"samba-common-bin", ver:"2:3.5.6~dfsg-3squeeze9", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"samba-dbg", ver:"2:3.5.6~dfsg-3squeeze9", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"samba-doc", ver:"2:3.5.6~dfsg-3squeeze9", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"samba-doc-pdf", ver:"2:3.5.6~dfsg-3squeeze9", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"samba-tools", ver:"2:3.5.6~dfsg-3squeeze9", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"smbclient", ver:"2:3.5.6~dfsg-3squeeze9", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"swat", ver:"2:3.5.6~dfsg-3squeeze9", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"winbind", ver:"2:3.5.6~dfsg-3squeeze9", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libnss-winbind", ver:"2:3.6.6-5", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpam-smbpass", ver:"2:3.6.6-5", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpam-winbind", ver:"2:3.6.6-5", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsmbclient", ver:"2:3.6.6-5", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsmbclient-dev", ver:"2:3.6.6-5", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libwbclient-dev", ver:"2:3.6.6-5", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libwbclient0", ver:"2:3.6.6-5", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"samba", ver:"2:3.6.6-5", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"samba-common", ver:"2:3.6.6-5", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"samba-common-bin", ver:"2:3.6.6-5", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"samba-dbg", ver:"2:3.6.6-5", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"samba-doc", ver:"2:3.6.6-5", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"samba-doc-pdf", ver:"2:3.6.6-5", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"samba-tools", ver:"2:3.6.6-5", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"smbclient", ver:"2:3.6.6-5", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"swat", ver:"2:3.6.6-5", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"winbind", ver:"2:3.6.6-5", rls:"DEB7.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
