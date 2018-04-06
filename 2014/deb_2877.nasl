# OpenVAS Vulnerability Test
# $Id: deb_2877.nasl 9354 2018-04-06 07:15:32Z cfischer $
# Auto-generated from advisory DSA 2877-1 using nvtgen 1.0
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
tag_solution  = "For the oldstable distribution (squeeze), these problems have been fixed in
version 1.4.28-2+squeeze1.6.

For the stable distribution (wheezy), these problems have been fixed in
version 1.4.31-4+deb7u3.

For the testing distribution (jessie), these problems will be fixed soon.

For the unstable distribution (sid), these problems have been fixed in
version 1.4.33-1+nmu3.

We recommend that you upgrade your lighttpd packages.";
tag_summary   = "Several vulnerabilities were discovered in the lighttpd web server.

CVE-2014-2323 
Jann Horn discovered that specially crafted host names can be used
to inject arbitrary MySQL queries in lighttpd servers using the
MySQL virtual hosting module (mod_mysql_vhost).

This only affects installations with the lighttpd-mod-mysql-vhost
binary package installed and in use.

CVE-2014-2324 
Jann Horn discovered that specially crafted host names can be used
to traverse outside of the document root under certain situations
in lighttpd servers using either the mod_mysql_vhost, mod_evhost,
or mod_simple_vhost virtual hosting modules.

Servers not using these modules are not affected.";
tag_vuldetect = "This check tests the installed software version using the apt package manager.";

if(description)
{
    script_oid("1.3.6.1.4.1.25623.1.0.702877");
    script_version("$Revision: 9354 $");
    script_cve_id("CVE-2014-2323", "CVE-2014-2324");
    script_name("Debian Security Advisory DSA 2877-1 (lighttpd - security update)");
    script_tag(name: "last_modification", value:"$Date: 2018-04-06 09:15:32 +0200 (Fri, 06 Apr 2018) $");
    script_tag(name: "creation_date", value:"2014-03-12 00:00:00 +0100 (Wed, 12 Mar 2014)");
    script_tag(name: "cvss_base", value:"7.5");
    script_tag(name: "cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

    script_xref(name: "URL", value: "http://www.debian.org/security/2014/dsa-2877.html");


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
if ((res = isdpkgvuln(pkg:"lighttpd", ver:"1.4.28-2+squeeze1.6", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lighttpd-doc", ver:"1.4.28-2+squeeze1.6", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lighttpd-mod-cml", ver:"1.4.28-2+squeeze1.6", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lighttpd-mod-magnet", ver:"1.4.28-2+squeeze1.6", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lighttpd-mod-mysql-vhost", ver:"1.4.28-2+squeeze1.6", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lighttpd-mod-trigger-b4-dl", ver:"1.4.28-2+squeeze1.6", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lighttpd-mod-webdav", ver:"1.4.28-2+squeeze1.6", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lighttpd", ver:"1.4.31-4+deb7u3", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lighttpd-doc", ver:"1.4.31-4+deb7u3", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lighttpd-mod-cml", ver:"1.4.31-4+deb7u3", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lighttpd-mod-magnet", ver:"1.4.31-4+deb7u3", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lighttpd-mod-mysql-vhost", ver:"1.4.31-4+deb7u3", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lighttpd-mod-trigger-b4-dl", ver:"1.4.31-4+deb7u3", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lighttpd-mod-webdav", ver:"1.4.31-4+deb7u3", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lighttpd", ver:"1.4.31-4+deb7u3", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lighttpd-doc", ver:"1.4.31-4+deb7u3", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lighttpd-mod-cml", ver:"1.4.31-4+deb7u3", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lighttpd-mod-magnet", ver:"1.4.31-4+deb7u3", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lighttpd-mod-mysql-vhost", ver:"1.4.31-4+deb7u3", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lighttpd-mod-trigger-b4-dl", ver:"1.4.31-4+deb7u3", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lighttpd-mod-webdav", ver:"1.4.31-4+deb7u3", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lighttpd", ver:"1.4.31-4+deb7u3", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lighttpd-doc", ver:"1.4.31-4+deb7u3", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lighttpd-mod-cml", ver:"1.4.31-4+deb7u3", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lighttpd-mod-magnet", ver:"1.4.31-4+deb7u3", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lighttpd-mod-mysql-vhost", ver:"1.4.31-4+deb7u3", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lighttpd-mod-trigger-b4-dl", ver:"1.4.31-4+deb7u3", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lighttpd-mod-webdav", ver:"1.4.31-4+deb7u3", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lighttpd", ver:"1.4.31-4+deb7u3", rls:"DEB7.3")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lighttpd-doc", ver:"1.4.31-4+deb7u3", rls:"DEB7.3")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lighttpd-mod-cml", ver:"1.4.31-4+deb7u3", rls:"DEB7.3")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lighttpd-mod-magnet", ver:"1.4.31-4+deb7u3", rls:"DEB7.3")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lighttpd-mod-mysql-vhost", ver:"1.4.31-4+deb7u3", rls:"DEB7.3")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lighttpd-mod-trigger-b4-dl", ver:"1.4.31-4+deb7u3", rls:"DEB7.3")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lighttpd-mod-webdav", ver:"1.4.31-4+deb7u3", rls:"DEB7.3")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
