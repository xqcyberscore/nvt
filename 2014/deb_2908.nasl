# OpenVAS Vulnerability Test
# $Id: deb_2908.nasl 9354 2018-04-06 07:15:32Z cfischer $
# Auto-generated from advisory DSA 2908-1 using nvtgen 1.0
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

tag_affected  = "openssl on Debian Linux";
tag_insight   = "This package contains the openssl binary and related tools.";
tag_solution  = "For the stable distribution (wheezy), these problems have been fixed in
version 1.0.1e-2+deb7u7.

For the testing distribution (jessie), these problems will be fixed
soon.

For the unstable distribution (sid), these problems have been fixed in
version 1.0.1g-3.

We recommend that you upgrade your openssl packages.";
tag_summary   = "Multiple vulnerabilities have been discovered in OpenSSL. The following
Common Vulnerabilities and Exposures project ids identify them:

CVE-2010-5298 
A read buffer can be freed even when it still contains data that is
used later on, leading to a use-after-free. Given a race condition in a
multi-threaded application it may permit an attacker to inject data from
one connection into another or cause denial of service.

CVE-2014-0076 
ECDSA nonces can be recovered through the Yarom/Benger FLUSH+RELOAD
cache side-channel attack.

A third issue, with no CVE id, is the missing detection of the
critical 
flag for the TSA extended key usage under certain cases.

Additionally, this update checks for more services that might need to
be restarted after upgrades of libssl, corrects the detection of
apache2 and postgresql, and adds support for the
'libraries/restart-without-asking' debconf configuration. This allows
services to be restarted on upgrade without prompting.

The oldstable distribution (squeeze) is not affected by CVE-2010-5298 

and it might be updated at a later time to address the remaining
vulnerabilities.";
tag_vuldetect = "This check tests the installed software version using the apt package manager.";

if(description)
{
    script_oid("1.3.6.1.4.1.25623.1.0.702908");
    script_version("$Revision: 9354 $");
    script_cve_id("CVE-2010-5298", "CVE-2014-0076");
    script_name("Debian Security Advisory DSA 2908-1 (openssl - security update)");
    script_tag(name: "last_modification", value:"$Date: 2018-04-06 09:15:32 +0200 (Fri, 06 Apr 2018) $");
    script_tag(name: "creation_date", value:"2014-04-17 00:00:00 +0200 (Thu, 17 Apr 2014)");
    script_tag(name:"cvss_base", value:"4.0");
    script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:P");

    script_xref(name: "URL", value: "http://www.debian.org/security/2014/dsa-2908.html");


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
if ((res = isdpkgvuln(pkg:"libssl-dev", ver:"1.0.1e-2+deb7u7", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libssl-doc", ver:"1.0.1e-2+deb7u7", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libssl1.0.0", ver:"1.0.1e-2+deb7u7", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libssl1.0.0-dbg", ver:"1.0.1e-2+deb7u7", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openssl", ver:"1.0.1e-2+deb7u7", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libssl-dev", ver:"1.0.1e-2+deb7u7", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libssl-doc", ver:"1.0.1e-2+deb7u7", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libssl1.0.0", ver:"1.0.1e-2+deb7u7", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libssl1.0.0-dbg", ver:"1.0.1e-2+deb7u7", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openssl", ver:"1.0.1e-2+deb7u7", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libssl-dev", ver:"1.0.1e-2+deb7u7", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libssl-doc", ver:"1.0.1e-2+deb7u7", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libssl1.0.0", ver:"1.0.1e-2+deb7u7", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libssl1.0.0-dbg", ver:"1.0.1e-2+deb7u7", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openssl", ver:"1.0.1e-2+deb7u7", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libssl-dev", ver:"1.0.1e-2+deb7u7", rls:"DEB7.3")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libssl-doc", ver:"1.0.1e-2+deb7u7", rls:"DEB7.3")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libssl1.0.0", ver:"1.0.1e-2+deb7u7", rls:"DEB7.3")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libssl1.0.0-dbg", ver:"1.0.1e-2+deb7u7", rls:"DEB7.3")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openssl", ver:"1.0.1e-2+deb7u7", rls:"DEB7.3")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
