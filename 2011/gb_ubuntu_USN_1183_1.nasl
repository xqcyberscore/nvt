###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1183_1.nasl 7964 2017-12-01 07:32:11Z santu $
#
# Ubuntu Update for linux USN-1183-1
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
tag_insight = "Dan Rosenberg discovered that multiple terminal ioctls did not correctly
  initialize structure memory. A local attacker could exploit this to read
  portions of kernel stack memory, leading to a loss of privacy.
  (CVE-2010-4076, CVE-2010-4077)

  Neil Horman discovered that NFSv4 did not correctly handle certain orders
  of operation with ACL data. A remote attacker with access to an NFSv4 mount
  could exploit this to crash the system, leading to a denial of service.
  (CVE-2011-1090)
  
  Timo Warns discovered that OSF partition parsing routines did not correctly
  clear memory. A local attacker with physical access could plug in a
  specially crafted block device to read kernel memory, leading to a loss of
  privacy. (CVE-2011-1163)
  
  Timo Warns discovered that the GUID partition parsing routines did not
  correctly validate certain structures. A local attacker with physical
  access could plug in a specially crafted block device to crash the system,
  leading to a denial of service. (CVE-2011-1577)
  
  Oliver Hartkopp and Dave Jones discovered that the CAN network driver did
  not correctly validate certain socket structures. If this driver was
  loaded, a local attacker could crash the system, leading to a denial of
  service. (CVE-2011-1598)
  
  Vasiliy Kulikov discovered that the AGP driver did not check the size of
  certain memory allocations. A local attacker with access to the video
  subsystem could exploit this to run the system out of memory, leading to a
  denial of service. (CVE-2011-1746)";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-1183-1";
tag_affected = "linux on Ubuntu 10.10";
tag_solution = "Please Install the Updated Packages.";


if(description)
{
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-1183-1/");
  script_id(840716);
  script_version("$Revision: 7964 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 08:32:11 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2011-08-12 15:49:01 +0200 (Fri, 12 Aug 2011)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_xref(name: "USN", value: "1183-1");
  script_cve_id("CVE-2010-4076", "CVE-2010-4077", "CVE-2011-1090", "CVE-2011-1163", "CVE-2011-1577", "CVE-2011-1598", "CVE-2011-1746");
  script_name("Ubuntu Update for linux USN-1183-1");

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

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.35-30-generic", ver:"2.6.35-30.56", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.35-30-generic-pae", ver:"2.6.35-30.56", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.35-30-omap", ver:"2.6.35-30.56", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.35-30-powerpc", ver:"2.6.35-30.56", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.35-30-powerpc-smp", ver:"2.6.35-30.56", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.35-30-powerpc64-smp", ver:"2.6.35-30.56", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.35-30-server", ver:"2.6.35-30.56", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.35-30-versatile", ver:"2.6.35-30.56", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.35-30-virtual", ver:"2.6.35-30.56", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
