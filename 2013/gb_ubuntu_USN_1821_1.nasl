###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1821_1.nasl 8448 2018-01-17 16:18:06Z teissa $
#
# Ubuntu Update for telepathy-idle USN-1821-1
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

tag_affected = "telepathy-idle on Ubuntu 13.04 ,
  Ubuntu 12.10 ,
  Ubuntu 12.04 LTS";
tag_insight = "It was discovered that telepathy-idle did not perform any server
  certificate validation when using SSL connections. If a remote attacker
  were able to perform a man-in-the-middle attack, this flaw could be
  exploited to alter or compromise confidential information.";
tag_solution = "Please Install the Updated Packages.";

if(description)
{
  script_id(841422);
  script_version("$Revision: 8448 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-17 17:18:06 +0100 (Wed, 17 Jan 2018) $");
  script_tag(name:"creation_date", value:"2013-05-13 12:43:40 +0530 (Mon, 13 May 2013)");
  script_cve_id("CVE-2007-6746");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_name("Ubuntu Update for telepathy-idle USN-1821-1");

  script_xref(name: "USN", value: "1821-1");
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-1821-1/");
  script_tag(name: "summary" , value: "Check for the Version of telepathy-idle");
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

  if ((res = isdpkgvuln(pkg:"telepathy-idle", ver:"0.1.11-2ubuntu0.1", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU12.10")
{

  if ((res = isdpkgvuln(pkg:"telepathy-idle", ver:"0.1.12-1ubuntu0.1", rls:"UBUNTU12.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU13.04")
{

  if ((res = isdpkgvuln(pkg:"telepathy-idle", ver:"0.1.14-1ubuntu0.1", rls:"UBUNTU13.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
