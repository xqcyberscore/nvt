# OpenVAS Vulnerability Test
# $Id: deb_3895.nasl 9356 2018-04-06 07:17:02Z cfischer $
# Auto-generated from advisory DSA 3895-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH http://greenbone.net
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
    script_oid("1.3.6.1.4.1.25623.1.0.703895");
    script_version("$Revision: 9356 $");
    script_cve_id("CVE-2017-9780");
    script_name("Debian Security Advisory DSA 3895-1 (flatpak - security update)");
    script_tag(name: "last_modification", value: "$Date: 2018-04-06 09:17:02 +0200 (Fri, 06 Apr 2018) $");
    script_tag(name: "creation_date", value: "2017-06-22 00:00:00 +0200 (Thu, 22 Jun 2017)");
    script_tag(name:"cvss_base", value:"7.2");
    script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
    script_tag(name: "solution_type", value: "VendorFix");
    script_tag(name: "qod_type", value: "package");

    script_xref(name: "URL", value: "http://www.debian.org/security/2017/dsa-3895.html");

    script_category(ACT_GATHER_INFO);

    script_copyright("Copyright (c) 2017 Greenbone Networks GmbH http://greenbone.net");
    script_family("Debian Local Security Checks");
    script_dependencies("gather-package-list.nasl");
    script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages");
    script_tag(name: "affected",  value: "flatpak on Debian Linux");
        script_tag(name: "insight",   value: "Flatpak installs, manages and runs sandboxed desktop application bundles.
Application bundles run partially isolated from the wider system, using
containerization techniques such as namespaces to prevent direct access
to system resources. Resources from outside the sandbox can be accessed
via 'portal' services, which are responsible for access control; for
example, the Documents portal displays an 'Open' dialog outside the
sandbox, then allows the application to access only the selected file.");
    script_tag(name: "solution",  value: "For the stable distribution (stretch), this problem has been fixed in
version 0.8.5-2+deb9u1.

For the unstable distribution (sid), this problem has been fixed in
version 0.8.7-1.

We recommend that you upgrade your flatpak packages.");
    script_tag(name: "summary",   value: "It was discovered that Flatpak, an application deployment framework for
desktop apps insufficiently restricted file permissinons in third-party
repositories, which could result in privilege escalation.");
    script_tag(name: "vuldetect", value: "This check tests the installed software version using the apt package manager.");

    exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if ((res = isdpkgvuln(pkg:"flatpak", ver:"0.8.5-2+deb9u1", rls_regex:"DEB9.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"flatpak-builder", ver:"0.8.5-2+deb9u1", rls_regex:"DEB9.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"flatpak-tests", ver:"0.8.5-2+deb9u1", rls_regex:"DEB9.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gir1.2-flatpak-1.0", ver:"0.8.5-2+deb9u1", rls_regex:"DEB9.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libflatpak-dev", ver:"0.8.5-2+deb9u1", rls_regex:"DEB9.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libflatpak-doc", ver:"0.8.5-2+deb9u1", rls_regex:"DEB9.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libflatpak0", ver:"0.8.5-2+deb9u1", rls_regex:"DEB9.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
