###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1172_1.nasl 7964 2017-12-01 07:32:11Z santu $
#
# Ubuntu Update for logrotate USN-1172-1
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_insight = "It was discovered that logrotate incorrectly handled the creation of new
  log files. Local users could possibly read log files if they were opened
  before permissions were in place. This issue only affected Ubuntu 8.04 LTS.
  (CVE-2011-1098)

  It was discovered that logrotate incorrectly handled certain log file
  names when used with the shred option. Local attackers able to create log
  files with specially crafted filenames could use this issue to execute
  arbitrary code. This issue only affected Ubuntu 10.04 LTS, 10.10, and
  11.04. (CVE-2011-1154)
  
  It was discovered that logrotate incorrectly handled certain malformed log
  filenames. Local attackers able to create log files with specially crafted
  filenames could use this issue to cause logrotate to stop processing log
  files, resulting in a denial of service. (CVE-2011-1155)
  
  It was discovered that logrotate incorrectly handled symlinks and hard
  links when processing log files. A local attacker having write access to
  a log file directory could use this issue to overwrite or read arbitrary
  files. This issue only affected Ubuntu 8.04 LTS. (CVE-2011-1548)";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-1172-1";
tag_affected = "logrotate on Ubuntu 11.04 ,
  Ubuntu 10.10 ,
  Ubuntu 10.04 LTS ,
  Ubuntu 8.04 LTS";
tag_solution = "Please Install the Updated Packages.";


if(description)
{
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-1172-1/");
  script_id(840705);
  script_version("$Revision: 7964 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 08:32:11 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2011-07-22 14:44:51 +0200 (Fri, 22 Jul 2011)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_xref(name: "USN", value: "1172-1");
  script_cve_id("CVE-2011-1098", "CVE-2011-1154", "CVE-2011-1155", "CVE-2011-1548");
  script_name("Ubuntu Update for logrotate USN-1172-1");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
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

if(release == "UBUNTU10.10")
{

  if ((res = isdpkgvuln(pkg:"logrotate", ver:"3.7.8-6ubuntu1.1", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU10.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"logrotate", ver:"3.7.8-4ubuntu2.2", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU11.04")
{

  if ((res = isdpkgvuln(pkg:"logrotate", ver:"3.7.8-6ubuntu3.1", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU8.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"logrotate", ver:"3.7.1-3ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
