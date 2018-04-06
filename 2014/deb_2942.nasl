# OpenVAS Vulnerability Test
# $Id: deb_2942.nasl 9354 2018-04-06 07:15:32Z cfischer $
# Auto-generated from advisory DSA 2942-1 using nvtgen 1.0
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

tag_affected  = "typo3-src on Debian Linux";
tag_insight   = "TYPO3 is a free Open Source content management system for enterprise purposes
on the web and in intranets. It offers full flexibility and extendability while
featuring an accomplished set of ready-made interfaces, functions and modules.";
tag_solution  = "For the stable distribution (wheezy), this problem has been fixed in
version 4.5.19+dfsg1-5+wheezy3.

For the testing distribution (jessie), this problem has been fixed in
version 4.5.34+dfsg1-1.

For the unstable distribution (sid), this problem has been fixed in
version 4.5.34+dfsg1-1.

We recommend that you upgrade your typo3-src packages.";
tag_summary   = "Multiple security issues have been discovered in the Typo3 CMS. More
information can be found in the upstream advisory:
http://typo3.org/teams/security/security-bulletins/typo3-core/typo3-core-sa-2014-001/";
tag_vuldetect = "This check tests the installed software version using the apt package manager.";

if(description)
{
    script_oid("1.3.6.1.4.1.25623.1.0.702942");
    script_version("$Revision: 9354 $");
    script_cve_id("CVE-2014-3941", "CVE-2014-3942", "CVE-2014-3943", "CVE-2014-3944", "CVE-2014-3945", "CVE-2014-3946");
    script_name("Debian Security Advisory DSA 2942-1 (typo3-src - security update)");
    script_tag(name: "last_modification", value:"$Date: 2018-04-06 09:15:32 +0200 (Fri, 06 Apr 2018) $");
    script_tag(name: "creation_date", value:"2014-06-01 00:00:00 +0200 (Sun, 01 Jun 2014)");
    script_tag(name:"cvss_base", value:"6.0");
    script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");

    script_xref(name: "URL", value: "http://www.debian.org/security/2014/dsa-2942.html");


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
if ((res = isdpkgvuln(pkg:"typo3", ver:"4.5.19+dfsg1-5+wheezy3", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"typo3-database", ver:"4.5.19+dfsg1-5+wheezy3", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"typo3-dummy", ver:"4.5.19+dfsg1-5+wheezy3", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"typo3-src-4.5", ver:"4.5.19+dfsg1-5+wheezy3", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"typo3", ver:"4.5.19+dfsg1-5+wheezy3", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"typo3-database", ver:"4.5.19+dfsg1-5+wheezy3", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"typo3-dummy", ver:"4.5.19+dfsg1-5+wheezy3", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"typo3-src-4.5", ver:"4.5.19+dfsg1-5+wheezy3", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"typo3", ver:"4.5.19+dfsg1-5+wheezy3", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"typo3-database", ver:"4.5.19+dfsg1-5+wheezy3", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"typo3-dummy", ver:"4.5.19+dfsg1-5+wheezy3", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"typo3-src-4.5", ver:"4.5.19+dfsg1-5+wheezy3", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"typo3", ver:"4.5.19+dfsg1-5+wheezy3", rls:"DEB7.3")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"typo3-database", ver:"4.5.19+dfsg1-5+wheezy3", rls:"DEB7.3")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"typo3-dummy", ver:"4.5.19+dfsg1-5+wheezy3", rls:"DEB7.3")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"typo3-src-4.5", ver:"4.5.19+dfsg1-5+wheezy3", rls:"DEB7.3")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
