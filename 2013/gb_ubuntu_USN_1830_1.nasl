###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1830_1.nasl 8448 2018-01-17 16:18:06Z teissa $
#
# Ubuntu Update for keystone USN-1830-1
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

tag_affected = "keystone on Ubuntu 13.04 ,
  Ubuntu 12.10 ,
  Ubuntu 12.04 LTS";
tag_insight = "Sam Stoelinga discovered that Keystone would not immediately invalidate
  tokens when deleting users via the v2 API. A deleted user would be able to
  continue to use resources until the token lifetime expired.";
tag_solution = "Please Install the Updated Packages.";

if(description)
{
  script_id(841431);
  script_version("$Revision: 8448 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-17 17:18:06 +0100 (Wed, 17 Jan 2018) $");
  script_tag(name:"creation_date", value:"2013-05-17 09:56:16 +0530 (Fri, 17 May 2013)");
  script_cve_id("CVE-2013-2059");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_name("Ubuntu Update for keystone USN-1830-1");

  script_xref(name: "USN", value: "1830-1");
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-1830-1/");
  script_tag(name: "summary" , value: "Check for the Version of keystone");
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

## Added check for Ubuntu 12.04
if(release == "UBUNTU12.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"python-keystone", ver:"2012.1.3+stable-20130423-f48dd0fc-0ubuntu1.1", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}

## Added check for Ubuntu 12.10
if(release == "UBUNTU12.10")
{

  if ((res = isdpkgvuln(pkg:"python-keystone", ver:"2012.2.3+stable-20130206-82c87e56-0ubuntu2.1", rls:"UBUNTU12.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU13.04")
{

  if ((res = isdpkgvuln(pkg:"python-keystone", ver:"1:2013.1-0ubuntu1.1", rls:"UBUNTU13.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
