###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1702_1.nasl 8509 2018-01-24 06:57:46Z teissa $
#
# Ubuntu Update for php5 USN-1702-1
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

tag_affected = "php5 on Ubuntu 12.04 LTS";
tag_insight = "It was discovered that PHP incorrectly handled the openssl_encrypt function
  when used with an empty string. An attacker could use this flaw to cause
  PHP to disclose arbitrary memory contents and possibly expose sensitive
  information.";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-1702-1/");
  script_id(841290);
  script_version("$Revision: 8509 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-24 07:57:46 +0100 (Wed, 24 Jan 2018) $");
  script_tag(name:"creation_date", value:"2013-01-24 09:36:48 +0530 (Thu, 24 Jan 2013)");
  script_cve_id("CVE-2012-6113");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_xref(name: "USN", value: "1702-1");
  script_name("Ubuntu Update for php5 USN-1702-1");

  script_tag(name: "summary" , value: "Check for the Version of php5");
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

if(release == "UBUNTU12.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"php5", ver:"5.3.10-1ubuntu3.5", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}