# OpenVAS Vulnerability Test
# $Id: deb_2773.nasl 9353 2018-04-06 07:14:20Z cfischer $
# Auto-generated from advisory DSA 2773-1 using nvtgen 1.0
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

tag_affected  = "gnupg on Debian Linux";
tag_insight   = "GnuPG is GNU's tool for secure communication and data storage.
It can be used to encrypt data and to create digital signatures.
It includes an advanced key management facility and is compliant
with the proposed OpenPGP Internet standard as described in RFC2440.";
tag_solution  = "For the oldstable distribution (squeeze), these problems have been fixed in
version 1.4.10-4+squeeze3.

For the stable distribution (wheezy), these problems have been fixed in
version 1.4.12-7+deb7u2.

For the unstable distribution (sid), these problems have been fixed in
version 1.4.15-1.

We recommend that you upgrade your gnupg packages.";
tag_summary   = "Two vulnerabilities were discovered in GnuPG, the GNU privacy guard,
a free PGP replacement. The Common Vulnerabilities and Exposures
project identifies the following problems:

CVE-2013-4351When a key or subkey had its key flags subpacket set to all bits
off, GnuPG currently would treat the key as having all bits set.
That is, where the owner wanted to indicate no use permitted,
GnuPG would interpret it as all use permitted. Such no use
permitted 
keys are rare and only used in very special circumstances.

CVE-2013-4402 
Infinite recursion in the compressed packet parser was possible
with crafted input data, which may be used to cause a denial of
service.";
tag_vuldetect = "This check tests the installed software version using the apt package manager.";

if(description)
{
    script_oid("1.3.6.1.4.1.25623.1.0.892773");
    script_version("$Revision: 9353 $");
    script_cve_id("CVE-2013-4402", "CVE-2013-4351");
    script_name("Debian Security Advisory DSA 2773-1 (gnupg - several vulnerabilities)");
    script_tag(name: "last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
    script_tag(name: "creation_date", value:"2013-10-10 00:00:00 +0200 (Thu, 10 Oct 2013)");
    script_tag(name:"cvss_base", value:"5.8");
    script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");

    script_xref(name: "URL", value: "http://www.debian.org/security/2013/dsa-2773.html");


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
if ((res = isdpkgvuln(pkg:"gnupg", ver:"1.4.10-4+squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gnupg-curl", ver:"1.4.10-4+squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gnupg-udeb", ver:"1.4.10-4+squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gpgv", ver:"1.4.10-4+squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gpgv-udeb", ver:"1.4.10-4+squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gnupg", ver:"1.4.12-7+deb7u2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gnupg-curl", ver:"1.4.12-7+deb7u2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gpgv", ver:"1.4.12-7+deb7u2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gpgv-win32", ver:"1.4.12-7+deb7u2", rls:"DEB7.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
