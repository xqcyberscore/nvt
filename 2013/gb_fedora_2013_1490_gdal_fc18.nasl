###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for gdal FEDORA-2013-1490
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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

include("revisions-lib.inc");
tag_insight = "Geospatial Data Abstraction Library (GDAL/OGR) is a cross platform
  C++ translator library for raster and vector geospatial data formats.
  As a library, it presents a single abstract data model to the calling
  application for all supported formats. It also comes with a variety of
  useful commandline utilities for data translation and processing.

  It provides the primary data access engine for many applications.
  GDAL/OGR is the most widely used geospatial data access library.";


tag_affected = "gdal on Fedora 18";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.fedoraproject.org/pipermail/package-announce/2013-February/098231.html");
  script_id(865306);
  script_version("$Revision: 2919 $");
  script_tag(name:"last_modification", value:"$Date: 2016-03-23 12:14:28 +0100 (Wed, 23 Mar 2016) $");
  script_tag(name:"creation_date", value:"2013-02-04 09:53:11 +0530 (Mon, 04 Feb 2013)");
  script_cve_id("CVE-2012-5127");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_xref(name: "FEDORA", value: "2013-1490");
  script_name("Fedora Update for gdal FEDORA-2013-1490");

  script_summary("Check for the Version of gdal");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("HostDetails/OS/cpe:/o:fedoraproject:fedora", "login/SSH/success", "ssh/login/release");
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");

res = "";
if(release == NULL){
  exit(0);
}

if(release == "FC18")
{
  if ((res = isrpmvuln(pkg:"gdal", rpm:"gdal~1.9.1~14.fc18.1", rls:"FC18")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
