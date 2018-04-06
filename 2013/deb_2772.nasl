# OpenVAS Vulnerability Test
# $Id: deb_2772.nasl 9353 2018-04-06 07:14:20Z cfischer $
# Auto-generated from advisory DSA 2772-1 using nvtgen 1.0
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

tag_affected  = "typo3-src on Debian Linux";
tag_insight   = "TYPO3 is a free Open Source content management system for enterprise purposes
on the web and in intranets. It offers full flexibility and extendability while
featuring an accomplished set of ready-made interfaces, functions and modules.";
tag_solution  = "For the stable distribution (wheezy), this problem has been fixed in
version 4.5.19+dfsg1-5+wheezy1.

For the testing distribution (jessie), this problem has been fixed in
version 4.5.29+dfsg1-1.

For the unstable distribution (sid), this problem has been fixed in
version 4.5.29+dfsg1-1.

We recommend that you upgrade your typo3-src packages.";
tag_summary   = "Markus Pieton and Vytautas Paulikas discovered that the embedded video
and audio player in the TYPO3 web content management system is suspectible
to cross-site-scripting.";
tag_vuldetect = "This check tests the installed software version using the apt package manager.";

if(description)
{
    script_oid("1.3.6.1.4.1.25623.1.0.892772");
    script_version("$Revision: 9353 $");
    script_cve_id("CVE-2013-1464");
    script_name("Debian Security Advisory DSA 2772-1 (typo3-src - cross-site scripting)");
    script_tag(name: "last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
    script_tag(name: "creation_date", value:"2013-10-10 00:00:00 +0200 (Thu, 10 Oct 2013)");
    script_tag(name: "cvss_base", value:"4.3");
    script_tag(name: "cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

    script_xref(name: "URL", value: "http://www.debian.org/security/2013/dsa-2772.html");


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
if ((res = isdpkgvuln(pkg:"typo3", ver:"4.5.19+dfsg1-5+wheezy1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"typo3-database", ver:"4.5.19+dfsg1-5+wheezy1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"typo3-dummy", ver:"4.5.19+dfsg1-5+wheezy1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"typo3-src-4.5", ver:"4.5.19+dfsg1-5+wheezy1", rls:"DEB7.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
