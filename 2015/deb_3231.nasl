# OpenVAS Vulnerability Test
# $Id: deb_3231.nasl 9355 2018-04-06 07:16:07Z cfischer $
# Auto-generated from advisory DSA 3231-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net
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


if(description)
{
    script_oid("1.3.6.1.4.1.25623.1.0.703231");
    script_version("$Revision: 9355 $");
    script_cve_id("CVE-2015-0248", "CVE-2015-0251");
    script_name("Debian Security Advisory DSA 3231-1 (subversion - security update)");
    script_tag(name: "last_modification", value: "$Date: 2018-04-06 09:16:07 +0200 (Fri, 06 Apr 2018) $");
    script_tag(name: "creation_date", value: "2015-04-21 00:00:00 +0200 (Tue, 21 Apr 2015)");
    script_tag(name:"cvss_base", value:"5.0");
    script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
    script_tag(name: "solution_type", value: "VendorFix");
    script_tag(name: "qod_type", value: "package");

    script_xref(name: "URL", value: "http://www.debian.org/security/2015/dsa-3231.html");


    script_category(ACT_GATHER_INFO);

    script_copyright("Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net");
    script_family("Debian Local Security Checks");
    script_dependencies("gather-package-list.nasl");
    script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages");
    script_tag(name: "affected",  value: "subversion on Debian Linux");
    script_tag(name: "insight",   value: "Subversion, also known as svn, is a
version control system much like the Concurrent Versions System (CVS). Version
control systems allow many individuals (who may be distributed geographically)
to collaborate on a set of files (typically source code). Subversion has
all the major features of CVS, plus certain new features that CVS
users often wish they had.");
    script_tag(name: "solution",  value: "For the stable distribution (wheezy),
these problems have been fixed in version 1.6.17dfsg-4+deb7u9.

For the upcoming stable distribution (jessie), these problems have been
fixed in version 1.8.10-6.

For the unstable distribution (sid), these problems have been fixed in
version 1.8.10-6.

We recommend that you upgrade your subversion packages.");
    script_tag(name: "summary",   value: "Several vulnerabilities were discovered
in Subversion, a version control system. The Common Vulnerabilities and Exposures
project identifies the following problems:

CVE-2015-0248 
Subversion mod_dav_svn and svnserve were vulnerable to a remotely
triggerable assertion DoS vulnerability for certain requests with
dynamically evaluated revision numbers.

CVE-2015-0251 
Subversion HTTP servers allow spoofing svn:author property values
for new revisions via specially crafted v1 HTTP protocol request
sequences.");
    script_tag(name: "vuldetect", value: "This check tests the installed software
version using the apt package manager.");
    exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if ((res = isdpkgvuln(pkg:"libapache2-svn", ver:"1.6.17dfsg-4+deb7u9", rls_regex:"DEB7.[0-9]")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsvn-dev", ver:"1.6.17dfsg-4+deb7u9", rls_regex:"DEB7.[0-9]")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsvn-doc", ver:"1.6.17dfsg-4+deb7u9", rls_regex:"DEB7.[0-9]")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsvn-java", ver:"1.6.17dfsg-4+deb7u9", rls_regex:"DEB7.[0-9]")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsvn-perl", ver:"1.6.17dfsg-4+deb7u9", rls_regex:"DEB7.[0-9]")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsvn-ruby", ver:"1.6.17dfsg-4+deb7u9", rls_regex:"DEB7.[0-9]")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsvn-ruby1.8:amd64", ver:"1.6.17dfsg-4+deb7u9", rls_regex:"DEB7.[0-9]")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsvn-ruby1.8:i386", ver:"1.6.17dfsg-4+deb7u9", rls_regex:"DEB7.[0-9]")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsvn1:amd64", ver:"1.6.17dfsg-4+deb7u9", rls_regex:"DEB7.[0-9]")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsvn1:i386", ver:"1.6.17dfsg-4+deb7u9", rls_regex:"DEB7.[0-9]")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"python-subversion", ver:"1.6.17dfsg-4+deb7u9", rls_regex:"DEB7.[0-9]")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"subversion", ver:"1.6.17dfsg-4+deb7u9", rls_regex:"DEB7.[0-9]")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"subversion-tools", ver:"1.6.17dfsg-4+deb7u9", rls_regex:"DEB7.[0-9]")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
