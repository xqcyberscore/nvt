###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_3426_1.nasl 7312 2017-09-28 11:22:27Z santu $
#
# Ubuntu Update for samba USN-3426-1
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843315");
  script_version("$Revision: 7312 $");
  script_tag(name:"last_modification", value:"$Date: 2017-09-28 13:22:27 +0200 (Thu, 28 Sep 2017) $");
  script_tag(name:"creation_date", value:"2017-09-24 10:00:43 +0200 (Sun, 24 Sep 2017)");
  script_cve_id("CVE-2017-12150", "CVE-2017-12151", "CVE-2017-12163");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("Ubuntu Update for samba USN-3426-1");
  script_tag(name: "summary", value: "Check the version of samba");
  script_tag(name: "vuldetect", value: "Get the installed version with the help of 
  detect NVT and check if the version is vulnerable or not."); 
  script_tag(name: "insight", value: "Stefan Metzmacher discovered that Samba 
  incorrectly enforced SMB signing in certain situations. A remote attacker could 
  use this issue to perform a man in the middle attack. (CVE-2017-12150) Stefan 
  Metzmacher discovered that Samba incorrectly handled encryption across DFS 
  redirects. A remote attacker could use this issue to perform a man in the middle 
  attack. (CVE-2017-12151) Yihan Lian and Zhibin Hu discovered that Samba 
  incorrectly handled memory when SMB1 is being used. A remote attacker could 
  possibly use this issue to obtain server memory contents. (CVE-2017-12163)"); 
  script_tag(name: "affected", value: "samba on Ubuntu 17.04 ,
  Ubuntu 16.04 LTS ,
  Ubuntu 14.04 LTS");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "USN", value: "3426-1");
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-3426-1/");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = get_kb_item("ssh/login/release");

res = "";
if(release == NULL){
  exit(0);
}

if(release == "UBUNTU14.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"samba", ver:"2:4.3.11+dfsg-0ubuntu0.14.04.12", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU17.04")
{

  if ((res = isdpkgvuln(pkg:"samba", ver:"2:4.5.8+dfsg-0ubuntu0.17.04.7", rls:"UBUNTU17.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU16.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"samba", ver:"2:4.3.11+dfsg-0ubuntu0.16.04.11", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}