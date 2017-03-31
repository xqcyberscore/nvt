###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for mysql-5.7 USN-3078-1
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.842882");
  script_version("$Revision: 4088 $");
  script_tag(name:"last_modification", value:"$Date: 2016-09-16 13:46:58 +0200 (Fri, 16 Sep 2016) $");
  script_tag(name:"creation_date", value:"2016-09-14 05:44:56 +0200 (Wed, 14 Sep 2016)");
  script_cve_id("CVE-2016-6662");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("Ubuntu Update for mysql-5.7 USN-3078-1");
  script_tag(name: "summary", value: "Check the version of mysql-5.7");
  script_tag(name: "vuldetect", value: "Get the installed version with the help
  of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "Dawid Golunski discovered that MySQL
  incorrectly handled configuration files. A remote attacker could possibly
  use this issue to execute arbitrary code with root privileges.

MySQL has been updated to 5.5.52 in Ubuntu 12.04 LTS and Ubuntu 14.04 LTS.
Ubuntu 16.04 LTS has been updated to MySQL 5.7.15.

In addition to security fixes, the updated packages contain bug fixes,
new features, and possibly incompatible changes.

Please see the following for more information:
http://dev.mysql.com/doc/relnotes/mysql/5.5/en/news-5-5-51.html
http://dev.mysql.com/doc/relnotes/mysql/5.5/en/news-5-5-52.html
http://dev.mysql.com/doc/relnotes/mysql/5.7/en/news-5-7-14.html
http://dev.mysql.com/doc/relnotes/mysql/5.7/en/news-5-7-15.html");
  script_tag(name: "affected", value: "mysql-5.7 on Ubuntu 16.04 LTS ,
  Ubuntu 14.04 LTS ,
  Ubuntu 12.04 LTS");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "USN", value: "3078-1");
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-3078-1/");
  script_tag(name:"solution_type", value:"VendorFix");
  script_summary("Check for the Version of mysql-5.7");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success", "HostDetails/OS/cpe:/o:canonical:ubuntu_linux", "ssh/login/release");
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

  if ((res = isdpkgvuln(pkg:"mysql-server-5.5", ver:"5.5.52-0ubuntu0.14.04.1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU12.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"mysql-server-5.5", ver:"5.5.52-0ubuntu0.12.04.1", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU16.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"mysql-server-5.7", ver:"5.7.15-0ubuntu0.16.04.1", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
