# OpenVAS Vulnerability Test
# $Id: deb_2721.nasl 9353 2018-04-06 07:14:20Z cfischer $
# Auto-generated from advisory DSA 2721-1 using nvtgen 1.0
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

tag_affected  = "nginx on Debian Linux";
tag_insight   = "Nginx ('engine X') is a high-performance web and reverse proxy server
created by Igor Sysoev. It can be used both as a standalone web server
and as a proxy to reduce the load on back-end HTTP or mail servers.";
tag_solution  = "For the stable distribution (wheezy), this problem has been fixed in
version 1.2.1-2.2+wheezy1.

For the unstable distribution (sid), this problem has been fixed in
version 1.4.1-1.

We recommend that you upgrade your nginx packages.";
tag_summary   = "A buffer overflow has been identified in nginx, a small, powerful,
scalable web/proxy server, when processing certain chunked transfer
encoding requests if proxy_pass to untrusted upstream HTTP servers is
used. An attacker may use this flaw to perform denial of service
attacks, disclose worker process memory, or possibly execute arbitrary
code.

The oldstable distribution (squeeze) is not affected by this problem.";
tag_vuldetect = "This check tests the installed software version using the apt package manager.";

if(description)
{
    script_oid("1.3.6.1.4.1.25623.1.0.892721");
    script_version("$Revision: 9353 $");
    script_cve_id("CVE-2013-2070");
    script_name("Debian Security Advisory DSA 2721-1 (nginx - buffer overflow)");
    script_tag(name: "last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
    script_tag(name: "creation_date", value:"2013-07-07 00:00:00 +0200 (Sun, 07 Jul 2013)");
    script_tag(name: "cvss_base", value:"5.8");
    script_tag(name: "cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:P");

    script_xref(name: "URL", value: "http://www.debian.org/security/2013/dsa-2721.html");


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
if ((res = isdpkgvuln(pkg:"nginx", ver:"1.2.1-2.2+wheezy1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nginx-common", ver:"1.2.1-2.2+wheezy1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nginx-doc", ver:"1.2.1-2.2+wheezy1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nginx-extras", ver:"1.2.1-2.2+wheezy1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nginx-extras-dbg", ver:"1.2.1-2.2+wheezy1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nginx-full", ver:"1.2.1-2.2+wheezy1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nginx-full-dbg", ver:"1.2.1-2.2+wheezy1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nginx-light", ver:"1.2.1-2.2+wheezy1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nginx-light-dbg", ver:"1.2.1-2.2+wheezy1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nginx-naxsi", ver:"1.2.1-2.2+wheezy1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nginx-naxsi-dbg", ver:"1.2.1-2.2+wheezy1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nginx-naxsi-ui", ver:"1.2.1-2.2+wheezy1", rls:"DEB7.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
