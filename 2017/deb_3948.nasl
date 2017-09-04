###############################################################################
# OpenVAS Vulnerability Test
# $Id: deb_3948.nasl 6981 2017-08-22 06:39:29Z asteins $
#
# Auto-generated from advisory DSA 3948-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.703948");
  script_version("$Revision: 6981 $");
  script_cve_id("CVE-2017-11721");
  script_name("Debian Security Advisory DSA 3948-1 (ioquake3 - security update)");
  script_tag(name:"last_modification", value:"$Date: 2017-08-22 08:39:29 +0200 (Tue, 22 Aug 2017) $");
  script_tag(name:"creation_date", value:"2017-08-19 00:00:00 +0200 (Sat, 19 Aug 2017)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"http://www.debian.org/security/2017/dsa-3948.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (c) 2017 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages");
  script_tag(name:"affected", value:"ioquake3 on Debian Linux");
  script_tag(name:"insight", value:"This package installs a modified version of the ioQuake3 game engine,
which can be used to play various games based on that engine, such as
OpenArena, Quake III: Arena, World of Padman and Urban Terror.");
  script_tag(name:"solution", value:"For the oldstable distribution (jessie), this problem has been fixed
in version 1.36+u20140802+gca9eebb-2+deb8u2.

For the stable distribution (stretch), this problem has been fixed in
version 1.36+u20161101+dfsg1-2+deb9u1.

We recommend that you upgrade your ioquake3 packages.");
  script_tag(name:"summary",  value:"A read buffer overflow was discovered in the idtech3 (Quake III Arena)
family of game engines. This allows remote attackers to cause a denial
of service (application crash) or possibly have unspecified other impact
via a crafted packet.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if ((res = isdpkgvuln(pkg:"ioquake3", ver:"1.36+u20140802+gca9eebb-2+deb8u2", rls_regex:"DEB8.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ioquake3-dbg", ver:"1.36+u20140802+gca9eebb-2+deb8u2", rls_regex:"DEB8.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ioquake3-server", ver:"1.36+u20140802+gca9eebb-2+deb8u2", rls_regex:"DEB8.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ioquake3", ver:"1.36+u20161101+dfsg1-2+deb9u1", rls_regex:"DEB9.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ioquake3-server", ver:"1.36+u20161101+dfsg1-2+deb9u1", rls_regex:"DEB9.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}

if (report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99); # Not vulnerable.
}
