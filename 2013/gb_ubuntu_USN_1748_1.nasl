###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1748_1.nasl 7958 2017-12-01 06:47:47Z santu $
#
# Ubuntu Update for thunderbird USN-1748-1
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
tag_insight = "Bobby Holley discovered vulnerabilities in Chrome Object Wrappers (COW) and
  System Only Wrappers (SOW). If a user were tricked into opening a specially
  crafted page and had scripting enabled, a remote attacker could exploit
  this to bypass security protections to obtain sensitive information or
  potentially execute code with the privileges of the user invoking
  Thunderbird. (CVE-2013-0773)

  Frederik Braun discovered that Thunderbird made the location of the active
  browser profile available to JavaScript workers. Scripting for Thunderbird
  is disabled by default in Ubuntu. (CVE-2013-0774)

  A use-after-free vulnerability was discovered in Thunderbird. An attacker
  could potentially exploit this to execute code with the privileges of the
  user invoking Thunderbird if scripting were enabled. (CVE-2013-0775)

  Michal Zalewski discovered that Thunderbird would not always show the
  correct address when cancelling a proxy authentication prompt. A remote
  attacker could exploit this to conduct URL spoofing and phishing attacks
  if scripting were enabled.
  (CVE-2013-0776)

  Abhishek Arya discovered several problems related to memory handling. If
  the user were tricked into opening a specially crafted page, an attacker
  could possibly exploit these to cause a denial of service via application
  crash, or potentially execute code with the privileges of the user invoking
  Thunderbird. (CVE-2013-0777, CVE-2013-0778, CVE-2013-0779, CVE-2013-0780,
  CVE-2013-0781, CVE-2013-0782)

  Olli Pettay, Christoph Diehl, Gary Kwong, Jesse Ruderman, Andrew McCreight,
  Joe Drew, Wayne Mery, Alon Zakai, Christian Holler, Gary Kwong, Luke
  Wagner, Terrence Cole, Timothy Nikkel, Bill McCloskey, and Nicolas Pierron
  discovered multiple memory safety issues affecting Thunderbird. If a user
  had scripting enabled and was tricked into opening a specially crafted
  page, an attacker could possibly exploit these to cause a denial of service
  via application crash. (CVE-2013-0783, CVE-2013-0784)";


tag_affected = "thunderbird on Ubuntu 12.10 ,
  Ubuntu 12.04 LTS ,
  Ubuntu 11.10 ,
  Ubuntu 10.04 LTS";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-1748-1/");
  script_id(841344);
  script_version("$Revision: 7958 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 07:47:47 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2013-03-01 11:08:05 +0530 (Fri, 01 Mar 2013)");
  script_cve_id("CVE-2013-0773","CVE-2013-0774","CVE-2013-0775","CVE-2013-0776",
                "CVE-2013-0777","CVE-2013-0778","CVE-2013-0779","CVE-2013-0780",
                "CVE-2013-0781","CVE-2013-0782","CVE-2013-0783","CVE-2013-0784");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name: "USN", value: "1748-1");
  script_name("Ubuntu Update for thunderbird USN-1748-1");

  script_summary("Check for the Version of thunderbird");
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

  if ((res = isdpkgvuln(pkg:"thunderbird", ver:"17.0.3+build1-0ubuntu0.12.04.1", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU11.10")
{

  if ((res = isdpkgvuln(pkg:"thunderbird", ver:"17.0.3+build1-0ubuntu0.11.10.1", rls:"UBUNTU11.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU10.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"thunderbird", ver:"17.0.3+build1-0ubuntu0.10.04.1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU12.10")
{

  if ((res = isdpkgvuln(pkg:"thunderbird", ver:"17.0.3+build1-0ubuntu0.12.10.1", rls:"UBUNTU12.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
