###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1681_2.nasl 7958 2017-12-01 06:47:47Z santu $
#
# Ubuntu Update for thunderbird USN-1681-2
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
tag_insight = "USN-1681-1 fixed vulnerabilities in Firefox. This update provides the
  corresponding updates for Thunderbird.

  Original advisory details:
  
  Christoph Diehl, Christian Holler, Mats Palmgren, Chiaki Ishikawa, Bill
  Gianopoulos, Benoit Jacob, Gary Kwong, Robert O'Callahan, Jesse Ruderman,
  and Julian Seward discovered multiple memory safety issues affecting
  Firefox. If the user were tricked into opening a specially crafted page, an
  attacker could possibly exploit these to cause a denial of service via
  application crash, or potentially execute code with the privileges of the
  user invoking Firefox. (CVE-2013-0769, CVE-2013-0749, CVE-2013-0770)
  
  Abhishek Arya discovered several user-after-free and buffer overflows in
  Firefox. An attacker could exploit these to cause a denial of service via
  application crash, or potentially execute code with the privileges of the
  user invoking Firefox. (CVE-2013-0760, CVE-2013-0761, CVE-2013-0762,
  CVE-2013-0763, CVE-2013-0766, CVE-2013-0767, CVE-2013-0771, CVE-2012-5829)
  
  A stack buffer was discovered in Firefox. If the user were tricked into
  opening a specially crafted page, an attacker could possibly exploit this
  to cause a denial of service via application crash, or potentially execute
  code with the privileges of the user invoking Firefox. (CVE-2013-0768)
  
  Masato Kinugawa discovered that Firefox did not always properly display URL
  values in the address bar. A remote attacker could exploit this to conduct
  URL spoofing and phishing attacks. (CVE-2013-0759)
  
  Atte Kettunen discovered that Firefox did not properly handle HTML tables
  with a large number of columns and column groups. If the user were tricked
  into opening a specially crafted page, an attacker could exploit this to
  cause a denial of service via application crash, or potentially execute
  code with the privileges of the user invoking Firefox. (CVE-2013-0744)
  
  Jerry Baker discovered that Firefox did not always properly handle
  threading when performing downloads over SSL connections. An attacker could
  exploit this to cause a denial of service via application crash.
  (CVE-2013-0764)
  
  Olli Pettay and Boris Zbarsky discovered flaws in the Javacript engine of
  Firefox. An attacker could cause a denial of service via application crash,
  or potentially execute code with the privileges of the user invoking
  Firefox. (CVE-2013-0745, CVE-2013-0746)
  
  Jesse Ruderman discovered a flaw in the way Firefox handled plugins.  If a
  user were tricked into opening a specially crafted pag ... 

  Description truncated, for more information please check the Reference URL";


tag_affected = "thunderbird on Ubuntu 12.10 ,
  Ubuntu 12.04 LTS ,
  Ubuntu 11.10 ,
  Ubuntu 10.04 LTS";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-1681-2/");
  script_id(841272);
  script_version("$Revision: 7958 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 07:47:47 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2013-01-11 16:49:34 +0530 (Fri, 11 Jan 2013)");
  script_cve_id("CVE-2013-0769", "CVE-2013-0749", "CVE-2013-0770", "CVE-2013-0760",
                "CVE-2013-0761", "CVE-2013-0762", "CVE-2013-0763", "CVE-2013-0766",
                "CVE-2013-0767", "CVE-2013-0771", "CVE-2012-5829", "CVE-2013-0768",
                "CVE-2013-0759", "CVE-2013-0744", "CVE-2013-0764", "CVE-2013-0745",
                "CVE-2013-0746", "CVE-2013-0747", "CVE-2013-0748", "CVE-2013-0750",
                "CVE-2013-0752", "CVE-2013-0757", "CVE-2013-0758", "CVE-2013-0753",
                "CVE-2013-0754", "CVE-2013-0755", "CVE-2013-0756");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name: "USN", value: "1681-2");
  script_name("Ubuntu Update for thunderbird USN-1681-2");

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

  if ((res = isdpkgvuln(pkg:"thunderbird", ver:"17.0.2+build1-0ubuntu0.12.04.1", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU11.10")
{

  if ((res = isdpkgvuln(pkg:"thunderbird", ver:"17.0.2+build1-0ubuntu0.11.10.1", rls:"UBUNTU11.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU10.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"thunderbird", ver:"17.0.2+build1-0ubuntu0.10.04.1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU12.10")
{

  if ((res = isdpkgvuln(pkg:"thunderbird", ver:"17.0.2+build1-0ubuntu0.12.10.1", rls:"UBUNTU12.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
