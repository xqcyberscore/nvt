# OpenVAS Vulnerability Test
# $Id: deb_2811.nasl 9353 2018-04-06 07:14:20Z cfischer $
# Auto-generated from advisory DSA 2811-1 using nvtgen 1.0
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
tag_solution  = "For the stable distribution (wheezy), these problems have been fixed in
version 31.0.1650.63-1~deb7u1.

For the testing distribution (jessie), these problems will be fixed soon.

For the unstable distribution (sid), these problems have been fixed in
version 31.0.1650.63-1.

We recommend that you upgrade your chromium-browser packages.";
tag_summary   = "Several vulnerabilities have been discovered in the chromium web browser.

CVE-2013-6634 
Andrey Labunets discovered that the wrong URL was used during
validation in the one-click sign on helper.

CVE-2013-6635 
cloudfuzzer discovered use-after-free issues in the InsertHTML and
Indent DOM editing commands.

CVE-2013-6636 
Bas Venis discovered an address bar spoofing issue.

CVE-2013-6637 
The chrome 31 development team discovered and fixed multiple issues
with potential security impact.

CVE-2013-6638 
Jakob Kummerow of the Chromium project discovered a buffer overflow in
the v8 javascript library.

CVE-2013-6639 
Jakob Kummerow of the Chromium project discovered an out-of-bounds
write in the v8 javascript library.

CVE-2013-6640 
Jakob Kummerow of the Chromium project discovered an out-of-bounds
read in the v8 javascript library.";
tag_vuldetect = "This check tests the installed software version using the apt package manager.";

if(description)
{
    script_oid("1.3.6.1.4.1.25623.1.0.892811");
    script_version("$Revision: 9353 $");
    script_cve_id("CVE-2013-6639", "CVE-2013-6636", "CVE-2013-6638", "CVE-2013-6640", "CVE-2013-6634", "CVE-2013-6637", "CVE-2013-6635");
    script_name("Debian Security Advisory DSA 2811-1 (chromium-browser - several vulnerabilities)");
    script_tag(name: "last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
    script_tag(name: "creation_date", value:"2013-12-07 00:00:00 +0100 (Sat, 07 Dec 2013)");
    script_tag(name:"cvss_base", value:"7.5");
    script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

    script_xref(name: "URL", value: "http://www.debian.org/security/2013/dsa-2811.html");


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
if ((res = isdpkgvuln(pkg:"chromium", ver:"31.0.1650.63-1~deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"chromium-browser", ver:"31.0.1650.63-1~deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"chromium-browser-dbg", ver:"31.0.1650.63-1~deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"chromium-browser-inspector", ver:"31.0.1650.63-1~deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"chromium-browser-l10n", ver:"31.0.1650.63-1~deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"chromium-dbg", ver:"31.0.1650.63-1~deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"chromium-inspector", ver:"31.0.1650.63-1~deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"chromium-l10n", ver:"31.0.1650.63-1~deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
