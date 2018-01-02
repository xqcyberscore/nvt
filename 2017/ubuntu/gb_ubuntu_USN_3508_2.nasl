###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_3508_2.nasl 8247 2017-12-26 13:32:16Z cfischer $
#
# Ubuntu Update for linux-hwe USN-3508-2
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.843396");
  script_version("$Revision: 8247 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-26 14:32:16 +0100 (Tue, 26 Dec 2017) $");
  script_tag(name:"creation_date", value:"2017-12-08 07:04:42 +0100 (Fri, 08 Dec 2017)");
  script_cve_id("CVE-2017-16939", "CVE-2017-1000405", "CVE-2017-12146");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("Ubuntu Update for linux-hwe USN-3508-2");
  script_tag(name: "summary", value: "Check the version of linux-hwe");
  script_tag(name: "vuldetect", value: "Get the installed version with the help of 
  detect NVT and check if the version is vulnerable or not."); 
  script_tag(name: "insight", value: "USN-3508-1 fixed vulnerabilities in the 
  Linux kernel for Ubuntu 17.04. This update provides the corresponding updates 
  for the Linux Hardware Enablement (HWE) kernel from Ubuntu 17.04 for Ubuntu 
  16.04 LTS. Mohamed Ghannam discovered that a use-after-free vulnerability 
  existed in the Netlink subsystem (XFRM) in the Linux kernel. A local attacker 
  could use this to cause a denial of service (system crash) or possibly execute 
  arbitrary code. (CVE-2017-16939) It was discovered that the Linux kernel did not 
  properly handle copy-on- write of transparent huge pages. A local attacker could 
  use this to cause a denial of service (application crashes) or possibly gain 
  administrative privileges. (CVE-2017-1000405) Yonggang Guo discovered that a 
  race condition existed in the driver subsystem in the Linux kernel. A local 
  attacker could use this to possibly gain administrative privileges. 
  (CVE-2017-12146)"); 
  script_tag(name: "affected", value: "linux-hwe on Ubuntu 16.04 LTS");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "USN", value: "3508-2");
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-3508-2/");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
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

if(release == "UBUNTU16.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"linux-image-4.10.0-42-generic", ver:"4.10.0-42.46~16.04.1", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-4.10.0-42-generic-lpae", ver:"4.10.0-42.46~16.04.1", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-4.10.0-42-lowlatency", ver:"4.10.0-42.46~16.04.1", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-generic-hwe-16.04", ver:"4.10.0.42.44", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-generic-lpae-hwe-16.04", ver:"4.10.0.42.44", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-lowlatency-hwe-16.04", ver:"4.10.0.42.44", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
