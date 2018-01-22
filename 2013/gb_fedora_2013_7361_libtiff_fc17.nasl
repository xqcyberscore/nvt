###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for libtiff FEDORA-2013-7361
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
tag_insight = "The libtiff package contains a library of functions for manipulating
  TIFF (Tagged Image File Format) image format files.  TIFF is a widely
  used file format for bitmapped images.  TIFF files usually end in the
  .tif extension and they are often quite large.

  The libtiff package should be installed if you need to manipulate TIFF
  format image files.";


tag_affected = "libtiff on Fedora 17";
tag_solution = "Please Install the Updated Packages.";

if(description)
{
  script_id(865635);
  script_version("$Revision: 8466 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-19 07:58:30 +0100 (Fri, 19 Jan 2018) $");
  script_tag(name:"creation_date", value:"2013-05-23 09:53:48 +0530 (Thu, 23 May 2013)");
  script_cve_id("CVE-2013-1960", "CVE-2013-1961", "CVE-2012-4447", "CVE-2012-4564",
                "CVE-2012-5581", "CVE-2012-3401", "CVE-2012-2088", "CVE-2012-2113");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Fedora Update for libtiff FEDORA-2013-7361");

  script_xref(name: "FEDORA", value: "2013-7361");
  script_xref(name: "URL" , value: "http://lists.fedoraproject.org/pipermail/package-announce/2013-May/105828.html");
  script_tag(name: "summary" , value: "Check for the Version of libtiff");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms");
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

if(release == "FC17")
{

  if ((res = isrpmvuln(pkg:"libtiff", rpm:"libtiff~3.9.7~2.fc17", rls:"FC17")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
