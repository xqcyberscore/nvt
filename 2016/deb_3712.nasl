# OpenVAS Vulnerability Test
# $Id: deb_3712.nasl 8168 2017-12-19 07:30:15Z teissa $
# Auto-generated from advisory DSA 3712-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH http://greenbone.net
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
    script_oid("1.3.6.1.4.1.25623.1.0.703712");
    script_version("$Revision: 8168 $");
    script_cve_id("CVE-2015-8971");
    script_name("Debian Security Advisory DSA 3712-1 (terminology - security update)");
    script_tag(name: "last_modification", value: "$Date: 2017-12-19 08:30:15 +0100 (Tue, 19 Dec 2017) $");
    script_tag(name: "creation_date", value: "2016-11-13 00:00:00 +0100 (Sun, 13 Nov 2016)");
    script_tag(name:"cvss_base", value:"4.6");
    script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
    script_tag(name: "solution_type", value: "VendorFix");
    script_tag(name: "qod_type", value: "package");

    script_xref(name: "URL", value: "http://www.debian.org/security/2016/dsa-3712.html");


    script_category(ACT_GATHER_INFO);

    script_copyright("Copyright (c) 2016 Greenbone Networks GmbH http://greenbone.net");
    script_family("Debian Local Security Checks");
    script_dependencies("gather-package-list.nasl");
    script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages");
    script_tag(name: "affected",  value: "terminology on Debian Linux");
        script_tag(name: "insight",   value: "It emulates a slightly extended vt100 with some extensions and bling

Most escapes supported by xterm, rxvt etc. work and Xterm 256 color
Background effects, Transparency, bitmap and scalable fonts supported
Themes for the layout and design, and a visual bell.
URL, file path and email address detection and link-handling
Inline display of link content
Multiple copy and paste selections and buffer support
Works in X11, Wayland and directly in the Linux framebuffer (fbcon)
Finger/touch controlled, scan scale by UI scaling factors
Render using OpenGL or OpenGL-ES2 or Software mode.
Can display inlined multimedia, multiple tabs and split into multiple panes
Block text selection. Drag and drop of text selections and links
Can stream media from URLs
Tab switcher has live thumbnail content
Single process, multiple windows/terminals support");
    script_tag(name: "solution",  value: "For the stable distribution (jessie), this problem has been fixed in
version 0.7.0-1+deb8u1.

For the unstable distribution (sid), this problem will be fixed soon.

We recommend that you upgrade your terminology packages.");
    script_tag(name: "summary",   value: "Nicolas Braud-Santoni discovered that incorrect sanitising of character
escape sequences in the Terminology terminal emulator may result in the
execution of arbitrary commands.");
    script_tag(name: "vuldetect", value: "This check tests the installed software version using the apt package manager.");

    exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if ((res = isdpkgvuln(pkg:"terminology", ver:"0.7.0-1+deb8u1", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"terminology-data", ver:"0.7.0-1+deb8u1", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
