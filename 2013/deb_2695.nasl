# OpenVAS Vulnerability Test
# $Id: deb_2695.nasl 9353 2018-04-06 07:14:20Z cfischer $
# Auto-generated from advisory DSA 2695-1 using nvtgen 1.0
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

tag_affected  = "chromium-browser on Debian Linux";
tag_insight   = "Chromium is an open-source browser project that aims to build a safer, faster,
and more stable way for all Internet users to experience the web.";
tag_solution  = "For the oldstable distribution (squeeze), the security support window
for Chromium has ended. Users of Chromium on oldstable are very highly
encouraged to upgrade to the current stable Debian release (wheezy).
Chromium security support for wheezy will last until the next stable
release (jessie), which is expected to happen sometime in 2015.

For the stable distribution (wheezy), these problems have been fixed in
version 27.0.1453.93-1~deb7u1.

For the testing distribution (jessie), these problems will be fixed soon.

For the unstable distribution (sid), these problems have been fixed in
version 27.0.1453.93-1.

We recommend that you upgrade your chromium-browser packages.";
tag_summary   = "Several vulnerabilities have been discovered in the Chromium web browser.
Multiple use-after-free, out-of-bounds read, memory safety, and
cross-site scripting issues were discovered and corrected.

CVE-2013-2837 
Use-after-free vulnerability in the SVG implementation allows remote
attackers to cause a denial of service or possibly have unspecified
other impact via unknown vectors.

CVE-2013-2838 
Google V8, as used in Chromium before 27.0.1453.93, allows
remote attackers to cause a denial of service (out-of-bounds read)
via unspecified vectors.

CVE-2013-2839 
Chromium before 27.0.1453.93 does not properly perform a cast
of an unspecified variable during handling of clipboard data, which
allows remote attackers to cause a denial of service or possibly
have other impact via unknown vectors.

CVE-2013-2840Use-after-free vulnerability in the media loader in Chromium
before 27.0.1453.93 allows remote attackers to cause a denial of
service or possibly have unspecified other impact via unknown
vectors, a different vulnerability than CVE-2013-2846 
.

CVE-2013-2841 
Use-after-free vulnerability in Chromium before 27.0.1453.93
allows remote attackers to cause a denial of service or possibly
have unspecified other impact via vectors related to the handling of
Pepper resources.

CVE-2013-2842 
Use-after-free vulnerability in Chromium before 27.0.1453.93
allows remote attackers to cause a denial of service or possibly
have unspecified other impact via vectors related to the handling of
widgets.

CVE-2013-2843 
Use-after-free vulnerability in Chromium before 27.0.1453.93
allows remote attackers to cause a denial of service or possibly
have unspecified other impact via vectors related to the handling of
speech data.

CVE-2013-2844 
Use-after-free vulnerability in the Cascading Style Sheets (CSS)
implementation in Chromium before 27.0.1453.93 allows remote
attackers to cause a denial of service or possibly have unspecified
other impact via vectors related to style resolution.

CVE-2013-2845 
The Web Audio implementation in Chromium before 27.0.1453.93
allows remote attackers to cause a denial of service (memory
corruption) or possibly have unspecified other impact via unknown
vectors.

CVE-2013-2846Use-after-free vulnerability in the media loader in Chromium
before 27.0.1453.93 allows remote attackers to cause a denial of
service or possibly have unspecified other impact via unknown
vectors, a different vulnerability than CVE-2013-2840 
.

CVE-2013-2847 
Race condition in the workers implementation in Chromium before
27.0.1453.93 allows remote attackers to cause a denial of service
(use-after-free and application crash) or possibly have unspecified
other impact via unknown vectors.

CVE-2013-2848 
The XSS Auditor in Chromium before 27.0.1453.93 might allow
remote attackers to obtain sensitive information via unspecified
vectors.

CVE-2013-2849 
Multiple cross-site scripting (XSS) vulnerabilities in Chromium
before 27.0.1453.93 allow user-assisted remote attackers to inject
arbitrary web script or HTML via vectors involving a (1)
drag-and-drop or (2) copy-and-paste operation.";
tag_vuldetect = "This check tests the installed software version using the apt package manager.";

if(description)
{
    script_oid("1.3.6.1.4.1.25623.1.0.892695");
    script_version("$Revision: 9353 $");
    script_cve_id("CVE-2013-2842", "CVE-2013-2848", "CVE-2013-2847", "CVE-2013-2841", "CVE-2013-2844", "CVE-2013-2840", "CVE-2013-2845", "CVE-2013-2839", "CVE-2013-2849", "CVE-2013-2838", "CVE-2013-2843", "CVE-2013-2837", "CVE-2013-2846");
    script_name("Debian Security Advisory DSA 2695-1 (chromium-browser - several issues)");
    script_tag(name: "last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
    script_tag(name: "creation_date", value:"2013-05-29 00:00:00 +0200 (Wed, 29 May 2013)");
    script_tag(name: "cvss_base", value:"7.5");
    script_tag(name: "cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

    script_xref(name: "URL", value: "http://www.debian.org/security/2013/dsa-2695.html");


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
if ((res = isdpkgvuln(pkg:"chromium", ver:"27.0.1453.93-1~deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"chromium-browser", ver:"27.0.1453.93-1~deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"chromium-browser-dbg", ver:"27.0.1453.93-1~deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"chromium-browser-inspector", ver:"27.0.1453.93-1~deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"chromium-browser-l10n", ver:"27.0.1453.93-1~deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"chromium-dbg", ver:"27.0.1453.93-1~deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"chromium-inspector", ver:"27.0.1453.93-1~deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"chromium-l10n", ver:"27.0.1453.93-1~deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
