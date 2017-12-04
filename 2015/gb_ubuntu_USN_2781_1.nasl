###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for mysql-5.6 USN-2781-1
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.842503");
  script_version("$Revision: 7956 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 06:53:44 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2015-10-27 07:08:00 +0100 (Tue, 27 Oct 2015)");
  script_cve_id("CVE-2015-4730", "CVE-2015-4766", "CVE-2015-4792", "CVE-2015-4800",
                "CVE-2015-4802", "CVE-2015-4815", "CVE-2015-4816", "CVE-2015-4819",
                "CVE-2015-4826", "CVE-2015-4830", "CVE-2015-4833", "CVE-2015-4836",
                "CVE-2015-4858", "CVE-2015-4861", "CVE-2015-4862", "CVE-2015-4864",
                "CVE-2015-4866", "CVE-2015-4870", "CVE-2015-4879", "CVE-2015-4890",
                "CVE-2015-4895", "CVE-2015-4904", "CVE-2015-4910", "CVE-2015-4913");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("Ubuntu Update for mysql-5.6 USN-2781-1");
  script_tag(name: "summary", value: "Check the version of mysql-5.6");
  script_tag(name: "vuldetect", value: "Get the installed version with the help of
detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "Multiple security issues were discovered in
MySQL and this update includes new upstream MySQL versions to fix these issues.

MySQL has been updated to 5.5.46 in Ubuntu 12.04 LTS and Ubuntu 14.04 LTS.
Ubuntu 15.04 and Ubuntu 15.10 have been updated to MySQL 5.6.27.

In addition to security fixes, the updated packages contain bug fixes,
new features, and possibly incompatible changes.

Please see the following for more information:
http://dev.mysql.com/doc/relnotes/mysql/5.5/en/news-5-5-45.html
http://dev.mysql.com/doc/relnotes/mysql/5.5/en/news-5-5-46.html
http://dev.mysql.com/doc/relnotes/mysql/5.6/en/news-5-6-26.html
http://dev.mysql.com/doc/relnotes/mysql/5.6/en/news-5-6-27.html
http://www.oracle.com/technetwork/topics/security/cpuoct2015-2367953.html");
  script_tag(name: "affected", value: "mysql-5.6 on Ubuntu 15.10 ,
  Ubuntu 15.04 ,
  Ubuntu 14.04 LTS ,
  Ubuntu 12.04 LTS");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");
  script_xref(name: "USN", value: "2781-1");
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-2781-1/");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
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

if(release == "UBUNTU15.04")
{

  if ((res = isdpkgvuln(pkg:"mysql-server-5.6", ver:"5.6.27-0ubuntu0.15.04.1", rls:"UBUNTU15.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU14.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"mysql-server-5.5", ver:"5.5.46-0ubuntu0.14.04.2", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU12.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"mysql-server-5.5", ver:"5.5.46-0ubuntu0.12.04.2", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU15.10")
{

  if ((res = isdpkgvuln(pkg:"mysql-server-5.6", ver:"5.6.27-0ubuntu1", rls:"UBUNTU15.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
