###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1232_1.nasl 7964 2017-12-01 07:32:11Z santu $
#
# Ubuntu Update for xorg-server USN-1232-1
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
tag_insight = "It was discovered that the X server incorrectly handled certain malformed
  input. An authorized attacker could exploit this to cause the X server to
  crash, leading to a denial or service, or possibly execute arbitrary code
  with root privileges. This issue only affected Ubuntu 10.04 LTS and 10.10.
  (CVE-2010-4818)

  It was discovered that the X server incorrectly handled certain malformed
  input. An authorized attacker could exploit this to cause the X server to
  crash, leading to a denial or service, or possibly read arbitrary data from
  the X server process. This issue only affected Ubuntu 10.04 LTS.
  (CVE-2010-4819)
  
  Vladz discovered that the X server incorrectly handled lock files. A local
  attacker could use this flaw to determine if a file existed or not.
  (CVE-2011-4028)
  
  Vladz discovered that the X server incorrectly handled setting lock file
  permissions. A local attacker could use this flaw to gain read permissions
  on arbitrary files and view sensitive information. (CVE-2011-4029)";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-1232-1";
tag_affected = "xorg-server on Ubuntu 11.04 ,
  Ubuntu 10.10 ,
  Ubuntu 10.04 LTS";
tag_solution = "Please Install the Updated Packages.";


if(description)
{
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-1232-1/");
  script_id(840780);
  script_version("$Revision: 7964 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 08:32:11 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2011-10-21 16:31:29 +0200 (Fri, 21 Oct 2011)");
  script_xref(name: "USN", value: "1232-1");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_cve_id("CVE-2010-4818", "CVE-2010-4819", "CVE-2011-4028", "CVE-2011-4029");
  script_name("Ubuntu Update for xorg-server USN-1232-1");

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

  if ((res = isdpkgvuln(pkg:"xserver-xorg-core", ver:"2:1.9.0-0ubuntu7.5", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU10.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"xserver-xorg-core", ver:"2:1.7.6-2ubuntu7.8", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU11.04")
{

  if ((res = isdpkgvuln(pkg:"xserver-xorg-core", ver:"2:1.10.1-1ubuntu1.3", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
