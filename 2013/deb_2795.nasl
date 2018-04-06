# OpenVAS Vulnerability Test
# $Id: deb_2795.nasl 9353 2018-04-06 07:14:20Z cfischer $
# Auto-generated from advisory DSA 2795-2 using nvtgen 1.0
# Script version: 2.0
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
tag_solution  = "For the oldstable distribution (squeeze), these problems have been fixed in
version 1.4.28-2+squeeze1.5.

For the stable distribution (wheezy), these problems have been fixed in
version 1.4.31-4+deb7u2.

For the testing distribution (jessie), these problems will be fixed soon.

For the unstable distribution (sid), these problems have been fixed in
version lighttpd_1.4.33-1+nmu1.

For the testing (jessie) and unstable (sid) distributions, the regression
problem will be fixed soon.

We recommend that you upgrade your lighttpd packages.";
tag_summary   = "Several vulnerabilities have been discovered in the lighttpd web server.

It was discovered that SSL connections with client certificates
stopped working after the DSA-2795-1 update of lighttpd. An upstream
patch has now been applied that provides an appropriate identifier for
client certificate verification.

CVE-2013-4508 
It was discovered that lighttpd uses weak ssl ciphers when SNI (Server
Name Indication) is enabled. This issue was solved by ensuring that
stronger ssl ciphers are used when SNI is selected.

CVE-2013-4559 
The clang static analyzer was used to discover privilege escalation
issues due to missing checks around lighttpd's setuid, setgid, and
setgroups calls. Those are now appropriately checked.

CVE-2013-4560 
The clang static analyzer was used to discover a use-after-free issue
when the FAM stat cache engine is enabled, which is now fixed.";
tag_vuldetect = "This check tests the installed software version using the apt package manager.";

if(description)
{
    script_oid("1.3.6.1.4.1.25623.1.0.892795");
    script_version("$Revision: 9353 $");
    script_cve_id("CVE-2013-4508", "CVE-2013-4560", "CVE-2013-4559");
    script_name("Debian Security Advisory DSA 2795-2 (lighttpd - several vulnerabilities)");
    script_tag(name: "last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
    script_tag(name: "creation_date", value:"2013-11-17 00:00:00 +0100 (Sun, 17 Nov 2013)");
    script_tag(name: "cvss_base", value:"7.6");
    script_tag(name: "cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");

    script_xref(name: "URL", value: "http://www.debian.org/security/2013/dsa-2795.html");


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
if ((res = isdpkgvuln(pkg:"lighttpd", ver:"1.4.28-2+squeeze1.5", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lighttpd-doc", ver:"1.4.28-2+squeeze1.5", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lighttpd-mod-cml", ver:"1.4.28-2+squeeze1.5", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lighttpd-mod-magnet", ver:"1.4.28-2+squeeze1.5", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lighttpd-mod-mysql-vhost", ver:"1.4.28-2+squeeze1.5", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lighttpd-mod-trigger-b4-dl", ver:"1.4.28-2+squeeze1.5", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lighttpd-mod-webdav", ver:"1.4.28-2+squeeze1.5", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lighttpd", ver:"1.4.31-4+deb7u2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lighttpd-doc", ver:"1.4.31-4+deb7u2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lighttpd-mod-cml", ver:"1.4.31-4+deb7u2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lighttpd-mod-magnet", ver:"1.4.31-4+deb7u2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lighttpd-mod-mysql-vhost", ver:"1.4.31-4+deb7u2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lighttpd-mod-trigger-b4-dl", ver:"1.4.31-4+deb7u2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lighttpd-mod-webdav", ver:"1.4.31-4+deb7u2", rls:"DEB7.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
