# OpenVAS Vulnerability Test
# $Id: deb_2831.nasl 9353 2018-04-06 07:14:20Z cfischer $
# Auto-generated from advisory DSA 2831-1 using nvtgen 1.0
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

include("revisions-lib.inc");

tag_affected  = "puppet on Debian Linux";
tag_insight   = "This package contains the startup script and compatbility scripts for the
puppet agent, which is the process responsible for configuring the local node.";
tag_solution  = "For the oldstable distribution (squeeze), this problem has been fixed in
version 2.6.2-5+squeeze9.

For the stable distribution (wheezy), this problem has been fixed in
version 2.7.23-1~deb7u2.

For the testing distribution (jessie), this problem has been fixed in
version 3.4.0-1.

For the unstable distribution (sid), this problem has been fixed in
version 3.4.0-1.

We recommend that you upgrade your puppet packages.";
tag_summary   = "An unsafe use of temporary files was discovered in Puppet, a tool for
centralized configuration management. An attacker can exploit this
vulnerability and overwrite an arbitrary file in the system.";
tag_vuldetect = "This check tests the installed software version using the apt package manager.";

if(description)
{
    script_oid("1.3.6.1.4.1.25623.1.0.702831");
    script_version("$Revision: 9353 $");
    script_cve_id("CVE-2013-4969");
    script_name("Debian Security Advisory DSA 2831-1 (puppet - insecure temporary files)");
    script_tag(name: "last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
    script_tag(name: "creation_date", value:"2013-12-31 00:00:00 +0100 (Tue, 31 Dec 2013)");
    script_tag(name:"cvss_base", value:"2.1");
    script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:P/A:N");

    script_xref(name: "URL", value: "http://www.debian.org/security/2013/dsa-2831.html");


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

include("pkg-lib-deb.inc");

res = "";
report = "";
if ((res = isdpkgvuln(pkg:"puppet", ver:"2.6.2-5+squeeze9", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"puppet-common", ver:"2.6.2-5+squeeze9", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"puppet-el", ver:"2.6.2-5+squeeze9", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"puppet-testsuite", ver:"2.6.2-5+squeeze9", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"puppetmaster", ver:"2.6.2-5+squeeze9", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vim-puppet", ver:"2.6.2-5+squeeze9", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"puppet", ver:"2.7.23-1~deb7u2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"puppet-common", ver:"2.7.23-1~deb7u2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"puppet-el", ver:"2.7.23-1~deb7u2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"puppet-testsuite", ver:"2.7.23-1~deb7u2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"puppetmaster", ver:"2.7.23-1~deb7u2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"puppetmaster-common", ver:"2.7.23-1~deb7u2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"puppetmaster-passenger", ver:"2.7.23-1~deb7u2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vim-puppet", ver:"2.7.23-1~deb7u2", rls:"DEB7.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
