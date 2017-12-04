###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1621_1.nasl 7960 2017-12-01 06:58:16Z santu $
#
# Ubuntu Update for mysql-5.5 USN-1621-1
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_insight = "Multiple security issues were discovered in MySQL and this update includes
  new upstream MySQL versions to fix these issues.

  MySQL has been updated to 5.1.66 in Ubuntu 10.04 LTS and Ubuntu 11.10.
  Ubuntu 12.04 LTS and Ubuntu 12.10 have been updated to MySQL 5.5.28.
  
  In addition to security fixes, the updated packages contain bug fixes, new
  features, and possibly incompatible changes.
  
  Please see the following for more information:
  http://dev.mysql.com/doc/refman/5.1/en/news-5-1-x.html
  http://www.oracle.com/technetwork/topics/security/cpuoct2012-1515893.html";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-1621-1";
tag_affected = "mysql-5.5 on Ubuntu 12.10 ,
  Ubuntu 12.04 LTS ,
  Ubuntu 11.10 ,
  Ubuntu 10.04 LTS";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-1621-1/");
  script_id(841207);
  script_version("$Revision: 7960 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 07:58:16 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2012-11-06 17:48:44 +0530 (Tue, 06 Nov 2012)");
  script_cve_id("CVE-2012-3144", "CVE-2012-3147", "CVE-2012-3149", "CVE-2012-3150",
                "CVE-2012-3156", "CVE-2012-3158", "CVE-2012-3160", "CVE-2012-3163",
                "CVE-2012-3166", "CVE-2012-3167", "CVE-2012-3173", "CVE-2012-3177",
                "CVE-2012-3180", "CVE-2012-3197");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_xref(name: "USN", value: "1621-1");
  script_name("Ubuntu Update for mysql-5.5 USN-1621-1");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages");
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
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

  if ((res = isdpkgvuln(pkg:"mysql-server-5.5", ver:"5.5.28-0ubuntu0.12.04.2", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU11.10")
{

  if ((res = isdpkgvuln(pkg:"mysql-server-5.1", ver:"5.1.66-0ubuntu0.11.10.2", rls:"UBUNTU11.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU10.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"mysql-server-5.1", ver:"5.1.66-0ubuntu0.10.04.1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU12.10")
{

  if ((res = isdpkgvuln(pkg:"mysql-server-5.5", ver:"5.5.28-0ubuntu0.12.10.1", rls:"UBUNTU12.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
