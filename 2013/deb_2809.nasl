# OpenVAS Vulnerability Test
# $Id: deb_2809.nasl 9353 2018-04-06 07:14:20Z cfischer $
# Auto-generated from advisory DSA 2809-1 using nvtgen 1.0
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

tag_affected  = "ruby1.8 on Debian Linux";
tag_insight   = "Ruby is the interpreted scripting language for quick and easy
object-oriented programming. It has many features to process text
files and to do system management tasks (as in perl). It is simple,
straight-forward, and extensible.";
tag_solution  = "For the oldstable distribution (squeeze), these problems have been fixed in
version 1.8.7.302-2squeeze2.

For the stable distribution (wheezy), these problems have been fixed in
version 1.8.7.358-7.1+deb7u1.

For the unstable distribution (sid), these problems have been fixed in
version 1.8.7.358-9.

We recommend that you upgrade your ruby1.8 packages.";
tag_summary   = "Several vulnerabilities have been discovered in the interpreter for the
Ruby language. The Common Vulnerabilities and Exposures project
identifies the following problems:

CVE-2013-1821 
Ben Murphy discovered that unrestricted entity expansion in REXML
can lead to a Denial of Service by consuming all host memory.

CVE-2013-4073 
William (B.J.) Snow Orvis discovered a vulnerability in the hostname
checking in Ruby's SSL client that could allow man-in-the-middle
attackers to spoof SSL servers via a crafted certificate issued by a
trusted certification authority.

CVE-2013-4164 
Charlie Somerville discovered that Ruby incorrectly handled floating
point number conversion. If an application using Ruby accepted
untrusted input strings and converted them to floating point
numbers, an attacker able to provide such input could cause the
application to crash or, possibly, execute arbitrary code with the
privileges of the application.";
tag_vuldetect = "This check tests the installed software version using the apt package manager.";

if(description)
{
    script_oid("1.3.6.1.4.1.25623.1.0.892809");
    script_version("$Revision: 9353 $");
    script_cve_id("CVE-2013-1821", "CVE-2013-4164", "CVE-2013-4073");
    script_name("Debian Security Advisory DSA 2809-1 (ruby1.8 - several vulnerabilities)");
    script_tag(name: "last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
    script_tag(name: "creation_date", value:"2013-12-04 00:00:00 +0100 (Wed, 04 Dec 2013)");
    script_tag(name: "cvss_base", value:"6.8");
    script_tag(name: "cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

    script_xref(name: "URL", value: "http://www.debian.org/security/2013/dsa-2809.html");


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
if ((res = isdpkgvuln(pkg:"libruby1.8", ver:"1.8.7.302-2squeeze2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libruby1.8-dbg", ver:"1.8.7.302-2squeeze2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libtcltk-ruby1.8", ver:"1.8.7.302-2squeeze2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ri1.8", ver:"1.8.7.302-2squeeze2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ruby1.8", ver:"1.8.7.302-2squeeze2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ruby1.8-dev", ver:"1.8.7.302-2squeeze2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ruby1.8-elisp", ver:"1.8.7.302-2squeeze2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ruby1.8-examples", ver:"1.8.7.302-2squeeze2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libruby1.8", ver:"1.8.7.358-7.1+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libruby1.8-dbg", ver:"1.8.7.358-7.1+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libtcltk-ruby1.8", ver:"1.8.7.358-7.1+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ri1.8", ver:"1.8.7.358-7.1+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ruby1.8", ver:"1.8.7.358-7.1+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ruby1.8-dev", ver:"1.8.7.358-7.1+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ruby1.8-examples", ver:"1.8.7.358-7.1+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ruby1.8-full", ver:"1.8.7.358-7.1+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
