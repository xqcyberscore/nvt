###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_2086_1.nasl 7957 2017-12-01 06:40:08Z santu $
#
# Ubuntu Update for mysql-5.5 USN-2086-1
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_id(841689);
  script_version("$Revision: 7957 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 07:40:08 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2014-01-27 11:21:43 +0530 (Mon, 27 Jan 2014)");
  script_cve_id("CVE-2013-5891", "CVE-2013-5908", "CVE-2014-0386", "CVE-2014-0393",
                "CVE-2014-0401", "CVE-2014-0402", "CVE-2014-0412", "CVE-2014-0420",
                "CVE-2014-0437");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_name("Ubuntu Update for mysql-5.5 USN-2086-1");

  tag_insight = "Multiple security issues were discovered in MySQL and this
update includes new upstream MySQL versions to fix these issues.

MySQL has been updated to 5.1.73 in Ubuntu 10.04 LTS. Ubuntu 12.04 LTS,
Ubuntu 12.10, and Ubuntu 13.10 have been updated to MySQL 5.5.35.

In addition to security fixes, the updated packages contain bug fixes,
new features, and possibly incompatible changes.

Please see the following for more information:
'http://dev.mysql.com/doc/relnotes/mysql/5.1/en/news-5-1-73.html'
'http://dev.mysql.com/doc/relnotes/mysql/5.5/en/news-5-5-35.html'
'http://www.oracle.com/technetwork/topics/security/cpujan2014-1972949.html'";

  tag_affected = "mysql-5.5 on Ubuntu 13.10 ,
  Ubuntu 12.10 ,
  Ubuntu 12.04 LTS ,
  Ubuntu 10.04 LTS";

  tag_solution = "Please Install the Updated Packages.";


  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name: "USN", value: "2086-1");
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-2086-1/");
  script_summary("Check for the Version of mysql-5.5");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
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

if(release == "UBUNTU12.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"mysql-server-5.5", ver:"5.5.35-0ubuntu0.12.04.1", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU10.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"mysql-server-5.1", ver:"5.1.73-0ubuntu0.10.04.1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU13.10")
{

  if ((res = isdpkgvuln(pkg:"mysql-server-5.5", ver:"5.5.35-0ubuntu0.13.10.1", rls:"UBUNTU13.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU12.10")
{

  if ((res = isdpkgvuln(pkg:"mysql-server-5.5", ver:"5.5.35-0ubuntu0.12.10.1", rls:"UBUNTU12.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
