# OpenVAS Vulnerability Test
# $Id: deb_2598.nasl 9353 2018-04-06 07:14:20Z cfischer $
# Auto-generated from advisory DSA 2598-1 using nvtgen 1.0
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

tag_affected  = "weechat on Debian Linux";
tag_insight   = "WeeChat (Wee Enhanced Environment for Chat) is a fast and light chat client
for many operating systems. Everything can be done with a keyboard.
It is customizable and extensible with plugins/scripts, and includes:

- nicklist
- smart hotlist
- infobar with highlight notification
- horizontal and vertical split
- double charset support (decode/encode)
- FIFO pipe for remote control
- and much more!";
tag_solution  = "For the stable distribution (squeeze), these problems have been fixed in
version 0.3.2-1+squeeze1.

For the testing distribution (wheezy), these problems have been fixed in
version 0.3.8-1+deb7u1.

For the unstable distribution (sid), these problems have been fixed in
version 0.3.9.2-1.

We recommend that you upgrade your weechat packages.";
tag_summary   = "Two security issues have been discovered in WeeChat, a fast, light and
extensible chat client:

CVE-2011-1428 
X.509 certificates were incorrectly validated.

CVE-2012-5534 
The hook_process function in the plugin API allowed the execution
of arbitrary shell commands.";
tag_vuldetect = "This check tests the installed software version using the apt package manager.";

if(description)
{
    script_oid("1.3.6.1.4.1.25623.1.0.892598");
    script_version("$Revision: 9353 $");
    script_cve_id("CVE-2011-1428", "CVE-2012-5534");
    script_name("Debian Security Advisory DSA 2598-1 (weechat - several vulnerabilities)");
    script_tag(name: "last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
    script_tag(name: "creation_date", value:"2013-01-05 00:00:00 +0100 (Sat, 05 Jan 2013)");
    script_tag(name: "cvss_base", value:"7.5");
    script_tag(name: "cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

    script_xref(name: "URL", value: "http://www.debian.org/security/2013/dsa-2598.html");


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
if ((res = isdpkgvuln(pkg:"weechat", ver:"0.3.2-1+squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"weechat-core", ver:"0.3.2-1+squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"weechat-curses", ver:"0.3.2-1+squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"weechat-dbg", ver:"0.3.2-1+squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"weechat-dev", ver:"0.3.2-1+squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"weechat-doc", ver:"0.3.2-1+squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"weechat-plugins", ver:"0.3.2-1+squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"weechat", ver:"0.3.8-1+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"weechat-core", ver:"0.3.8-1+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"weechat-curses", ver:"0.3.8-1+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"weechat-dbg", ver:"0.3.8-1+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"weechat-dev", ver:"0.3.8-1+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"weechat-doc", ver:"0.3.8-1+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"weechat-plugins", ver:"0.3.8-1+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
