###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1926_1.nasl 8526 2018-01-25 06:57:37Z teissa $
#
# Ubuntu Update for spice USN-1926-1
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

if(description)
{
  script_id(841530);
  script_version("$Revision: 8526 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-25 07:57:37 +0100 (Thu, 25 Jan 2018) $");
  script_tag(name:"creation_date", value:"2013-08-16 09:04:23 +0530 (Fri, 16 Aug 2013)");
  script_cve_id("CVE-2013-4130");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Ubuntu Update for spice USN-1926-1");

  tag_insight = "David Gibson discovered that SPICE incorrectly handled certain network
errors. An attacker could use this issue to cause the SPICE server to
crash, resulting in a denial of service.";

  tag_affected = "spice on Ubuntu 13.04";

  tag_solution = "Please Install the Updated Packages.";


  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name: "USN", value: "1926-1");
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-1926-1/");
  script_tag(name: "summary" , value: "Check for the Version of spice");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages");
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

  if ((res = isdpkgvuln(pkg:"libspice-server1", ver:"0.12.2-0nocelt2expubuntu1.1", rls:"UBUNTU13.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
