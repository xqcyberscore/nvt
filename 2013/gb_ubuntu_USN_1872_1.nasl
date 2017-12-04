###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1872_1.nasl 7958 2017-12-01 06:47:47Z santu $
#
# Ubuntu Update for php5 USN-1872-1
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

tag_affected = "php5 on Ubuntu 13.04";
tag_insight = "It was discovered that PHP incorrectly handled the quoted_printable_encode
  function. An attacker could use this flaw to cause PHP to crash, resulting
  in a denial of service, or to possibly execute arbitrary code.";
tag_solution = "Please Install the Updated Packages.";

if(description)
{
  script_id(841470);
  script_version("$Revision: 7958 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 07:47:47 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2013-06-13 10:17:43 +0530 (Thu, 13 Jun 2013)");
  script_cve_id("CVE-2013-2110");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Ubuntu Update for php5 USN-1872-1");

  script_xref(name: "USN", value: "1872-1");
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-1872-1/");
  script_summary("Check for the Version of php5");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages");
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("pkg-lib-deb.inc");

release = get_kb_item("ssh/login/release");

res = "";
if(release == NULL){
  exit(0);
}

if(release == "UBUNTU13.04")
{
  ## Updated package name 5.4.9-4ubuntu2.1 to 5.4.9-4ubuntu2
  if ((res = isdpkgvuln(pkg:"php5", ver:"5.4.9-4ubuntu2", rls:"UBUNTU13.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
