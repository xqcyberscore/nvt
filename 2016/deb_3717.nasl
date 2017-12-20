# OpenVAS Vulnerability Test
# $Id: deb_3717.nasl 8168 2017-12-19 07:30:15Z teissa $
# Auto-generated from advisory DSA 3717-1 using nvtgen 1.0
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
    script_oid("1.3.6.1.4.1.25623.1.0.703717");
    script_version("$Revision: 8168 $");
    
    script_name("Debian Security Advisory DSA 3717-1 (gst-plugins-bad1.0 / gst-plugins-bad0.10 - security update)");
    script_tag(name: "last_modification", value: "$Date: 2017-12-19 08:30:15 +0100 (Tue, 19 Dec 2017) $");
    script_tag(name: "creation_date", value: "2016-11-17 00:00:00 +0100 (Thu, 17 Nov 2016)");
    script_tag(name: "cvss_base", value: "10.0");
    script_tag(name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C");
    script_tag(name: "solution_type", value: "VendorFix");
    script_tag(name: "qod_type", value: "package");

    script_xref(name: "URL", value: "http://www.debian.org/security/2016/dsa-3717.html");

    script_category(ACT_GATHER_INFO);

    script_copyright("Copyright (c) 2016 Greenbone Networks GmbH http://greenbone.net");
    script_family("Debian Local Security Checks");
    script_dependencies("gather-package-list.nasl");
    script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages");
    script_tag(name: "affected",  value: "gst-plugins-bad1.0 / gst-plugins-bad0.10 on Debian Linux");
    script_tag(name: "solution",  value: "For the stable distribution (jessie), this problem has been fixed in
version 1.4.4-2.1+deb8u1 of gst-plugins-bad1.0 and version
0.10.23-7.4+deb8u2 of gst-plugins-bad0.10.

For the unstable distribution (sid), this problem has been fixed in
version 1.10.1-1 of gst-plugins-bad1.0.

We recommend that you upgrade your gst-plugins-bad1.0 packages.");
    script_tag(name: "summary",   value: "Chris Evans discovered that the GStreamer plugin to decode VMware screen
capture files allowed the execution of arbitrary code.");
    script_tag(name: "vuldetect", value: "This check tests the installed software version using the apt package manager.");

    exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if ((res = isdpkgvuln(pkg:"gstreamer0.10-plugins-bad", ver:"0.10.23-7.4+deb8u2", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gstreamer0.10-plugins-bad-dbg", ver:"0.10.23-7.4+deb8u2", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gstreamer0.10-plugins-bad-doc", ver:"0.10.23-7.4+deb8u2", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgstreamer-plugins-bad0.10-0", ver:"0.10.23-7.4+deb8u2", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgstreamer-plugins-bad0.10-dev", ver:"0.10.23-7.4+deb8u2", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
