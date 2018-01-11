###############################################################################
# OpenVAS Vulnerability Test
# $Id: deb_dla_1228.nasl 8344 2018-01-09 13:13:38Z teissa $
#
# Auto-generated from advisory DLA 1228-1 using nvtgen 1.0
# Script version:1.0
# #
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH http://greenbone.net
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891228");
  script_version("$Revision: 8344 $");
  script_cve_id("CVE-2017-1000456");
  script_name("Debian Lts Announce DLA 1228-1 ([SECURITY] [DLA 1228-1] poppler security update)");
  script_tag(name:"last_modification", value:"$Date: 2018-01-09 14:13:38 +0100 (Tue, 09 Jan 2018) $");
  script_tag(name:"creation_date", value:"2018-01-09 00:00:00 +0100 (Tue, 09 Jan 2018)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2018/01/msg00001.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages");
  script_tag(name:"affected", value:"poppler on Debian Linux");
  script_tag(name:"insight", value:"Poppler is a PDF rendering library based on the xpdf PDF viewer.");
  script_tag(name:"solution", value:"For Debian 7 'Wheezy', this issue has been fixed in poppler version
0.18.4-6+deb7u5.

We recommend that you upgrade your poppler packages.");
  script_tag(name:"summary",  value:"Jason Crain discovered a overflow vulnerability in the poppler PDF
rendering library.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if ((res = isdpkgvuln(pkg:"gir1.2-poppler-0.18", ver:"0.18.4-6+deb7u5", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpoppler-cpp-dev", ver:"0.18.4-6+deb7u5", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpoppler-cpp0", ver:"0.18.4-6+deb7u5", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpoppler-dev", ver:"0.18.4-6+deb7u5", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpoppler-glib-dev", ver:"0.18.4-6+deb7u5", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpoppler-glib8", ver:"0.18.4-6+deb7u5", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpoppler-private-dev", ver:"0.18.4-6+deb7u5", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpoppler-qt4-3", ver:"0.18.4-6+deb7u5", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpoppler-qt4-dev", ver:"0.18.4-6+deb7u5", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpoppler19", ver:"0.18.4-6+deb7u5", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"poppler-dbg", ver:"0.18.4-6+deb7u5", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"poppler-utils", ver:"0.18.4-6+deb7u5", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}

if (report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99); # Not vulnerable.
}
