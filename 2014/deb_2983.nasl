# OpenVAS Vulnerability Test
# $Id: deb_2983.nasl 9354 2018-04-06 07:15:32Z cfischer $
# Auto-generated from advisory DSA 2983-1 using nvtgen 1.0
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

tag_affected  = "drupal7 on Debian Linux";
tag_insight   = "Drupal is a dynamic web site platform which allows an individual or
community of users to publish, manage and organize a variety of
content, Drupal integrates many popular features of content
management systems, weblogs, collaborative tools and discussion-based
community software into one easy-to-use package.";
tag_solution  = "For the stable distribution (wheezy), this problem has been fixed in
version 7.14-2+deb7u5.

For the testing distribution (jessie), this problem has been fixed in
version 7.29-1.

For the unstable distribution (sid), this problem has been fixed in
version 7.29-1.

We recommend that you upgrade your drupal7 packages.";
tag_summary   = "Multiple security issues have been discovered in the Drupal content
management system, ranging from denial of service to cross-site
scripting. More information can be found at https://www.drupal.org/SA-CORE-2014-003 
.";
tag_vuldetect = "This check tests the installed software version using the apt package manager.";

if(description)
{
    script_oid("1.3.6.1.4.1.25623.1.0.702983");
    script_version("$Revision: 9354 $");
    script_cve_id("CVE-2014-5019", "CVE-2014-5020", "CVE-2014-5021", "CVE-2014-5022");
    script_name("Debian Security Advisory DSA 2983-1 (drupal7 - security update)");
    script_tag(name: "last_modification", value:"$Date: 2018-04-06 09:15:32 +0200 (Fri, 06 Apr 2018) $");
    script_tag(name: "creation_date", value:"2014-07-20 00:00:00 +0200 (Sun, 20 Jul 2014)");
    script_tag(name:"cvss_base", value:"5.0");
    script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

    script_xref(name: "URL", value: "http://www.debian.org/security/2014/dsa-2983.html");


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
if ((res = isdpkgvuln(pkg:"drupal7", ver:"7.14-2+deb7u5", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"drupal7", ver:"7.14-2+deb7u5", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"drupal7", ver:"7.14-2+deb7u5", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"drupal7", ver:"7.14-2+deb7u5", rls:"DEB7.3")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
