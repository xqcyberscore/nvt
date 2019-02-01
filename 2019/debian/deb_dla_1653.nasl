###############################################################################
# OpenVAS Vulnerability Test
# $Id: deb_dla_1653.nasl 13393 2019-02-01 07:05:30Z cfischer $
#
# Auto-generated from advisory DLA 1653-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.891653");
  script_version("$Revision: 13393 $");
  script_cve_id("CVE-2017-18359");
  script_name("Debian LTS Advisory ([SECURITY] [DLA 1653-1] postgis security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-02-01 08:05:30 +0100 (Fri, 01 Feb 2019) $");
  script_tag(name:"creation_date", value:"2019-02-01 00:00:00 +0100 (Fri, 01 Feb 2019)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2019/01/msg00030.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (c) 2019 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8\.[0-9]+");
  script_tag(name:"affected", value:"postgis on Debian Linux");
  script_tag(name:"insight", value:"PostGIS adds support for geographic objects to the PostgreSQL
object-relational database. In effect, PostGIS 'spatially enables'
the PostgreSQL server, allowing it to be used as a backend spatial
database for geographic information systems (GIS), much like ESRI's
SDE or Oracle's Spatial extension. PostGIS follows the OpenGIS
'Simple Features Specification for SQL'.");
  script_tag(name:"solution", value:"For Debian 8 'Jessie', this problem has been fixed in version
2.1.4+dfsg-3+deb8u1.

We recommend that you upgrade your postgis packages.");
  script_tag(name:"summary", value:"It was found that the function ST_AsX3D in PostGIS, a module that
adds spatial objects to the PostgreSQL object-relational database, did
not handle empty values properly, allowing malicious users to cause
denial of service or possibly other unspecified behaviour.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if ((res = isdpkgvuln(pkg:"liblwgeom-2.1.4", ver:"2.1.4+dfsg-3+deb8u1", rls_regex:"DEB8\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"liblwgeom-dev", ver:"2.1.4+dfsg-3+deb8u1", rls_regex:"DEB8\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpostgis-java", ver:"2.1.4+dfsg-3+deb8u1", rls_regex:"DEB8\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpostgis-java-doc", ver:"2.1.4+dfsg-3+deb8u1", rls_regex:"DEB8\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgis", ver:"2.1.4+dfsg-3+deb8u1", rls_regex:"DEB8\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgis-doc", ver:"2.1.4+dfsg-3+deb8u1", rls_regex:"DEB8\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql-9.4-postgis-2.1", ver:"2.1.4+dfsg-3+deb8u1", rls_regex:"DEB8\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql-9.4-postgis-2.1-scripts", ver:"2.1.4+dfsg-3+deb8u1", rls_regex:"DEB8\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql-9.4-postgis-scripts", ver:"2.1.4+dfsg-3+deb8u1", rls_regex:"DEB8\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}

if (report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}
