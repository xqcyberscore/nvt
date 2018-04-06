# OpenVAS Vulnerability Test
# $Id: deb_2660.nasl 9353 2018-04-06 07:14:20Z cfischer $
# Auto-generated from advisory DSA 2660-1 using nvtgen 1.0
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

tag_affected  = "curl on Debian Linux";
tag_insight   = "curl is a client to get files from servers using any of the supported
protocols. The command is designed to work without user interaction
or any kind of interactivity.";
tag_solution  = "For the stable distribution (squeeze), this problem has been fixed in
version 7.21.0-2.1+squeeze3.

For the testing distribution (wheezy), this problem has been fixed in
version 7.26.0-1+wheezy2.

For the unstable distribution (sid), this problem has been fixed in
version 7.29.0-2.1.

We recommend that you upgrade your curl packages.";
tag_summary   = "Yamada Yasuharu discovered that cURL, an URL transfer library, is
vulnerable to expose potentially sensitive information when doing
requests across domains with matching tails. Due to a bug in the
tailmatch function when matching domain names, it was possible that
cookies set for a domain ample.com could accidentally also be sent
by libcurl when communicating with example.com 
.

Both curl the command line tool and applications using the libcurl
library are vulnerable.";
tag_vuldetect = "This check tests the installed software version using the apt package manager.";

if(description)
{
    script_oid("1.3.6.1.4.1.25623.1.0.892660");
    script_version("$Revision: 9353 $");
    script_cve_id("CVE-2013-1944");
    script_name("Debian Security Advisory DSA 2660-1 (curl - exposure of sensitive information)");
    script_tag(name: "last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
    script_tag(name: "creation_date", value:"2013-04-20 00:00:00 +0200 (Sat, 20 Apr 2013)");
    script_tag(name: "cvss_base", value:"5.0");
    script_tag(name: "cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

    script_xref(name: "URL", value: "http://www.debian.org/security/2013/dsa-2660.html");


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
if ((res = isdpkgvuln(pkg:"curl", ver:"7.21.0-2.1+squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libcurl3", ver:"7.21.0-2.1+squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libcurl3-dbg", ver:"7.21.0-2.1+squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libcurl3-gnutls", ver:"7.21.0-2.1+squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libcurl4-gnutls-dev", ver:"7.21.0-2.1+squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libcurl4-openssl-dev", ver:"7.21.0-2.1+squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"curl", ver:"7.26.0-1+wheezy2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libcurl3", ver:"7.26.0-1+wheezy2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libcurl3-dbg", ver:"7.26.0-1+wheezy2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libcurl3-gnutls", ver:"7.26.0-1+wheezy2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libcurl3-nss", ver:"7.26.0-1+wheezy2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libcurl4-gnutls-dev", ver:"7.26.0-1+wheezy2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libcurl4-nss-dev", ver:"7.26.0-1+wheezy2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libcurl4-openssl-dev", ver:"7.26.0-1+wheezy2", rls:"DEB7.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
