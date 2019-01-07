###############################################################################
# OpenVAS Vulnerability Test
# $Id: deb_dla_1629.nasl 12953 2019-01-07 07:55:18Z cfischer $
#
# Auto-generated from advisory DLA 1629-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.891629");
  script_version("$Revision: 12953 $");
  script_cve_id("CVE-2019-3498");
  script_name("Debian LTS Advisory ([SECURITY] [DLA 1629-1] python-django security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-01-07 08:55:18 +0100 (Mon, 07 Jan 2019) $");
  script_tag(name:"creation_date", value:"2019-01-07 00:00:00 +0100 (Mon, 07 Jan 2019)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2019/01/msg00005.html");
  script_xref(name:"URL", value:"https://www.djangoproject.com/weblog/2019/jan/04/security-releases/");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (c) 2019 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8\.[0-9]+");
  script_tag(name:"affected", value:"python-django on Debian Linux");
  script_tag(name:"insight", value:"Django is a high-level web application framework that loosely follows the
model-view-controller design pattern.");
  script_tag(name:"solution", value:"For Debian 8 'Jessie', this issue has been fixed in python-django
version 1.7.11-1+deb8u4.

We recommend that you upgrade your python-django packages.");
  script_tag(name:"summary", value:"It was discovered that there was a content-spoofing vulnerability in the
default 404 pages in the Django web development framework.

Please see the references for more information.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if ((res = isdpkgvuln(pkg:"python-django", ver:"1.7.11-1+deb8u4", rls_regex:"DEB8\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"python-django-common", ver:"1.7.11-1+deb8u4", rls_regex:"DEB8\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"python-django-doc", ver:"1.7.11-1+deb8u4", rls_regex:"DEB8\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"python3-django", ver:"1.7.11-1+deb8u4", rls_regex:"DEB8\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}

if (report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}
