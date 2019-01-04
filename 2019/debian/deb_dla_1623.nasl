###############################################################################
# OpenVAS Vulnerability Test
# $Id: deb_dla_1623.nasl 12931 2019-01-03 16:36:54Z cfischer $
#
# Auto-generated from advisory DLA 1623-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2019 Greenbone Networks GmbH http://greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.891623");
  script_version("$Revision: 12931 $");
  script_cve_id("CVE-2018-20482");
  script_name("Debian LTS Advisory ([SECURITY] [DLA 1623-1] tar security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-01-03 17:36:54 +0100 (Thu, 03 Jan 2019) $");
  script_tag(name:"creation_date", value:"2019-01-03 00:00:00 +0100 (Thu, 03 Jan 2019)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2018/12/msg00023.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (c) 2019 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8\.[0-9]+");
  script_tag(name:"affected", value:"tar on Debian Linux");
  script_tag(name:"insight", value:"Tar is a program for packaging a set of files as a single archive in tar
format. The function it performs is conceptually similar to cpio, and to
things like PKZIP in the DOS world. It is heavily used by the Debian package
management system, and is useful for performing system backups and exchanging
sets of files with others.");
  script_tag(name:"solution", value:"For Debian 8 'Jessie', this issue has been fixed in tar version
1.27.1-2+deb8u2.

We recommend that you upgrade your tar packages.");
  script_tag(name:"summary", value:"It was discovered that there was a potential denial of service
vulnerability in tar, the GNU version of the tar UNIX archiving
utility.

The --sparse argument looped endlessly if the file shrank whilst
it was being read. Tar would only break out of this endless loop
if the file grew again to (or beyond) its original end of file.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if ((res = isdpkgvuln(pkg:"tar", ver:"1.27.1-2+deb8u2", rls_regex:"DEB8\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"tar-scripts", ver:"1.27.1-2+deb8u2", rls_regex:"DEB8\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}

if (report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}
