# OpenVAS Vulnerability Test
# $Id: deb_2626.nasl 9353 2018-04-06 07:14:20Z cfischer $
# Auto-generated from advisory DSA 2626-1 using nvtgen 1.0
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
tag_solution  = "For the stable distribution (squeeze), these problems have been fixed in
version 1.4.28-2+squeeze1.2.

For the testing distribution (wheezy), and the unstable distribution (sid)
these problems have been fixed in version 1.4.30-1.

We recommend that you upgrade your lighttpd packages.";
tag_summary   = "Several vulnerabilities were discovered in the TLS/SSL protocol. This
update addresses these protocol vulnerabilities in lighttpd.

CVE-2009-3555 
Marsh Ray, Steve Dispensa, and Martin Rex discovered that the TLS
and SSLv3 protocols do not properly associate renegotiation
handshakes with an existing connection, which allows man-in-the-middle
attackers to insert data into HTTPS sessions. This issue is solved
in lighttpd by disabling client initiated renegotiation by default.

Those users that do actually need such renegotiations, can reenable
them via the new ssl.disable-client-renegotiation 
parameter.

CVE-2012-4929Juliano Rizzo and Thai Duong discovered a weakness in the TLS/SSL
protocol when using compression. This side channel attack, dubbed
CRIME 
, allows eavesdroppers to gather information to recover the
original plaintext in the protocol. This update disables compression.";
tag_vuldetect = "This check tests the installed software version using the apt package manager.";

if(description)
{
    script_oid("1.3.6.1.4.1.25623.1.0.892626");
    script_version("$Revision: 9353 $");
    script_cve_id("CVE-2012-4929", "CVE-2009-3555");
    script_name("Debian Security Advisory DSA 2626-1 (lighttpd - several issues)");
    script_tag(name: "last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
    script_tag(name: "creation_date", value:"2013-02-17 00:00:00 +0100 (Sun, 17 Feb 2013)");
    script_tag(name: "cvss_base", value:"5.8");
    script_tag(name: "cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");

    script_xref(name: "URL", value: "http://www.debian.org/security/2013/dsa-2626.html");


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
if ((res = isdpkgvuln(pkg:"lighttpd", ver:"1.4.28-2+squeeze1.2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lighttpd-doc", ver:"1.4.28-2+squeeze1.2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lighttpd-mod-cml", ver:"1.4.28-2+squeeze1.2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lighttpd-mod-magnet", ver:"1.4.28-2+squeeze1.2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lighttpd-mod-mysql-vhost", ver:"1.4.28-2+squeeze1.2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lighttpd-mod-trigger-b4-dl", ver:"1.4.28-2+squeeze1.2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lighttpd-mod-webdav", ver:"1.4.28-2+squeeze1.2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lighttpd", ver:"1.4.30-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lighttpd-doc", ver:"1.4.30-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lighttpd-mod-cml", ver:"1.4.30-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lighttpd-mod-magnet", ver:"1.4.30-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lighttpd-mod-mysql-vhost", ver:"1.4.30-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lighttpd-mod-trigger-b4-dl", ver:"1.4.30-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lighttpd-mod-webdav", ver:"1.4.30-1", rls:"DEB7.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
