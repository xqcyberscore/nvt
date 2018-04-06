# OpenVAS Vulnerability Test
# $Id: deb_3001.nasl 9354 2018-04-06 07:15:32Z cfischer $
# Auto-generated from advisory DSA 3001-1 using nvtgen 1.0
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

tag_affected  = "wordpress on Debian Linux";
tag_insight   = "WordPress is a full featured web blogging tool:

* Instant publishing (no rebuilding)
* Comment pingback support with spam protection
* Non-crufty URLs
* Themable
* Plugin support";
tag_solution  = "For the stable distribution (wheezy), these problems have been fixed in
version 3.6.1+dfsg-1~deb7u4.

For the unstable distribution (sid), these problems have been fixed in
version 3.9.2+dfsg-1.

We recommend that you upgrade your wordpress packages.";
tag_summary   = "Multiple security issues have been discovered in Wordpress, a web
blogging tool, resulting in denial of service or information disclosure.
More information can be found in the upstream advisory at
https://wordpress.org/news/2014/08/wordpress-3-9-2/ 
.";
tag_vuldetect = "This check tests the installed software version using the apt package manager.";

if(description)
{
    script_oid("1.3.6.1.4.1.25623.1.0.703001");
    script_version("$Revision: 9354 $");
    script_cve_id("CVE-2014-2053", "CVE-2014-5204", "CVE-2014-5205", "CVE-2014-5240", "CVE-2014-5265", "CVE-2014-5266");
    script_name("Debian Security Advisory DSA 3001-1 (wordpress - security update)");
    script_tag(name: "last_modification", value:"$Date: 2018-04-06 09:15:32 +0200 (Fri, 06 Apr 2018) $");
    script_tag(name: "creation_date", value:"2014-08-09 00:00:00 +0200 (Sat, 09 Aug 2014)");
    script_tag(name:"cvss_base", value:"7.5");
    script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

    script_xref(name: "URL", value: "http://www.debian.org/security/2014/dsa-3001.html");


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
if ((res = isdpkgvuln(pkg:"wordpress", ver:"3.6.1+dfsg-1~deb7u4", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"wordpress-l10n", ver:"3.6.1+dfsg-1~deb7u4", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"wordpress", ver:"3.6.1+dfsg-1~deb7u4", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"wordpress-l10n", ver:"3.6.1+dfsg-1~deb7u4", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"wordpress", ver:"3.6.1+dfsg-1~deb7u4", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"wordpress-l10n", ver:"3.6.1+dfsg-1~deb7u4", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"wordpress", ver:"3.6.1+dfsg-1~deb7u4", rls:"DEB7.3")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"wordpress-l10n", ver:"3.6.1+dfsg-1~deb7u4", rls:"DEB7.3")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
