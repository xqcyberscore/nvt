# OpenVAS Vulnerability Test
# $Id: deb_2649.nasl 9353 2018-04-06 07:14:20Z cfischer $
# Auto-generated from advisory DSA 2649-1 using nvtgen 1.0
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

tag_affected  = "lighttpd on Debian Linux";
tag_insight   = "lighttpd is a small webserver and fast webserver developed with
security in mind and a lot of features.
It has support for

* CGI, FastCGI and SSI
* virtual hosts
* URL rewriting
* authentication (plain files, htpasswd, ldap)
* transparent content compression
* conditional configuration

and configuration is straight-forward and easy.";
tag_solution  = "For the stable distribution (squeeze), this problem has been fixed in
version 1.4.28-2+squeeze1.3.

For the testing distribution (wheezy), this problem has been fixed in
version 1.4.31-4.

For the unstable distribution (sid), this problem has been fixed in
version 1.4.31-4.

We recommend that you upgrade your lighttpd packages.";
tag_summary   = "Stefan Bühler discovered that the Debian specific configuration file for
lighttpd webserver FastCGI PHP support used a fixed socket name in the
world-writable /tmp directory. A symlink attack or a race condition could be
exploited by a malicious user on the same machine to take over the PHP control
socket and for example force the webserver to use a different PHP version.

As the fix is in a configuration file lying in /etc, the update won't be
enforced if the file has been modified by the administrator. In that case, care
should be taken to manually apply the fix.";
tag_vuldetect = "This check tests the installed software version using the apt package manager.";

if(description)
{
    script_oid("1.3.6.1.4.1.25623.1.0.892649");
    script_version("$Revision: 9353 $");
    script_cve_id("CVE-2013-1427");
    script_name("Debian Security Advisory DSA 2649-1 (lighttpd - fixed socket name in world-writable directory)");
    script_tag(name: "last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
    script_tag(name: "creation_date", value:"2013-03-15 00:00:00 +0100 (Fri, 15 Mar 2013)");
    script_tag(name: "cvss_base", value:"1.9");
    script_tag(name: "cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:P/A:N");

    script_xref(name: "URL", value: "http://www.debian.org/security/2013/dsa-2649.html");


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
if ((res = isdpkgvuln(pkg:"lighttpd", ver:"1.4.28-2+squeeze1.3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lighttpd-doc", ver:"1.4.28-2+squeeze1.3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lighttpd-mod-cml", ver:"1.4.28-2+squeeze1.3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lighttpd-mod-magnet", ver:"1.4.28-2+squeeze1.3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lighttpd-mod-mysql-vhost", ver:"1.4.28-2+squeeze1.3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lighttpd-mod-trigger-b4-dl", ver:"1.4.28-2+squeeze1.3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lighttpd-mod-webdav", ver:"1.4.28-2+squeeze1.3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lighttpd", ver:"1.4.31-4", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lighttpd-doc", ver:"1.4.31-4", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lighttpd-mod-cml", ver:"1.4.31-4", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lighttpd-mod-magnet", ver:"1.4.31-4", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lighttpd-mod-mysql-vhost", ver:"1.4.31-4", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lighttpd-mod-trigger-b4-dl", ver:"1.4.31-4", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lighttpd-mod-webdav", ver:"1.4.31-4", rls:"DEB7.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
