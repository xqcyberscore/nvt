###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1800_1.nasl 7958 2017-12-01 06:47:47Z santu $
#
# Ubuntu Update for haproxy USN-1800-1
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
tag_insight = "It was discovered that HAProxy incorrectly handled configurations where
  global.tune.bufsize was set to a value higher than the default. A remote
  attacker could use this issue to cause a denial of service, or possibly
  execute arbitrary code. (CVE-2012-2942)

  Yves Lafon discovered that HAProxy incorrectly handled HTTP keywords in TCP
  inspection rules when HTTP keep-alive is enabled. A remote attacker could
  use this issue to cause a denial of service, or possibly execute arbitrary
  code. (CVE-2013-1912)";


tag_affected = "haproxy on Ubuntu 12.10 ,
  Ubuntu 12.04 LTS ,
  Ubuntu 11.10";
tag_solution = "Please Install the Updated Packages.";

if(description)
{
  script_id(841399);
  script_version("$Revision: 7958 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 07:47:47 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2013-04-19 10:08:56 +0530 (Fri, 19 Apr 2013)");
  script_cve_id("CVE-2012-2942", "CVE-2013-1912");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_name("Ubuntu Update for haproxy USN-1800-1");

  script_xref(name: "USN", value: "1800-1");
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-1800-1/");
  script_summary("Check for the Version of haproxy");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages");
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

  if ((res = isdpkgvuln(pkg:"haproxy", ver:"1.4.18-0ubuntu1.1", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU11.10")
{

  if ((res = isdpkgvuln(pkg:"haproxy", ver:"1.4.15-1ubuntu0.1", rls:"UBUNTU11.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU12.10")
{

  if ((res = isdpkgvuln(pkg:"haproxy", ver:"1.4.18-0ubuntu2.1", rls:"UBUNTU12.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
