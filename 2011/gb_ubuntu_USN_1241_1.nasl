###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1241_1.nasl 7964 2017-12-01 07:32:11Z santu $
#
# Ubuntu Update for linux-fsl-imx51 USN-1241-1
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
tag_insight = "It was discovered that the Stream Control Transmission Protocol (SCTP)
  implementation incorrectly calculated lengths. If the net.sctp.addip_enable
  variable was turned on, a remote attacker could send specially crafted
  traffic to crash the system. (CVE-2011-1573)

  Ryan Sweat discovered that the kernel incorrectly handled certain VLAN
  packets. On some systems, a remote attacker could send specially crafted
  traffic to crash the system, leading to a denial of service.
  (CVE-2011-1576)
  
  Timo Warns discovered that the EFI GUID partition table was not correctly
  parsed. A physically local attacker that could insert mountable devices
  could exploit this to crash the system or possibly gain root privileges.
  (CVE-2011-1776)
  
  Dan Rosenberg discovered that the IPv4 diagnostic routines did not
  correctly validate certain requests. A local attacker could exploit this to
  consume CPU resources, leading to a denial of service. (CVE-2011-2213)
  
  Vasiliy Kulikov discovered that taskstats did not enforce access
  restrictions. A local attacker could exploit this to read certain
  information, leading to a loss of privacy. (CVE-2011-2494)
  
  Vasiliy Kulikov discovered that /proc/PID/io did not enforce access
  restrictions. A local attacker could exploit this to read certain
  information, leading to a loss of privacy. (CVE-2011-2495)
  
  Robert Swiecki discovered that mapping extensions were incorrectly handled.
  A local attacker could exploit this to crash the system, leading to a
  denial of service. (CVE-2011-2496)
  
  Dan Rosenberg discovered that the Bluetooth stack incorrectly handled
  certain L2CAP requests. If a system was using Bluetooth, a remote attacker
  could send specially crafted traffic to crash the system or gain root
  privileges. (CVE-2011-2497)
  
  It was discovered that the wireless stack incorrectly verified SSID
  lengths. A local attacker could exploit this to cause a denial of service
  or gain root privileges. (CVE-2011-2517)
  
  Ben Pfaff discovered that Classless Queuing Disciplines (qdiscs) were being
  incorrectly handled. A local attacker could exploit this to crash the
  system, leading to a denial of service. (CVE-2011-2525)
  
  It was discovered that the EXT4 filesystem contained multiple off-by-one
  flaws. A local attacker could exploit this to crash the system, leading to
  a denial of service. (CVE-2011-2695)
  
  Herbert Xu discovered that certain fields were incorrectly handled when
  Generic Receive Offload (CVE-2011-2723)
  
  Christian Ohm discovered that the perf command looks for configuration
  files in the curre ... 

  Description truncated, for more information please check the Reference URL";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-1241-1";
tag_affected = "linux-fsl-imx51 on Ubuntu 10.04 LTS";
tag_solution = "Please Install the Updated Packages.";


if(description)
{
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-1241-1/");
  script_id(840790);
  script_version("$Revision: 7964 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 08:32:11 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2011-10-31 13:45:00 +0100 (Mon, 31 Oct 2011)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name: "USN", value: "1241-1");
  script_cve_id("CVE-2011-1573", "CVE-2011-1576", "CVE-2011-1776", "CVE-2011-2213",
                "CVE-2011-2494", "CVE-2011-2495", "CVE-2011-2496", "CVE-2011-2497",
                "CVE-2011-2517", "CVE-2011-2525", "CVE-2011-2695", "CVE-2011-2723",
                "CVE-2011-2905", "CVE-2011-2909", "CVE-2011-2928", "CVE-2011-3188",
                "CVE-2011-3191", "CVE-2011-3363");
  script_name("Ubuntu Update for linux-fsl-imx51 USN-1241-1");

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

if(release == "UBUNTU10.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.31-611-imx51", ver:"2.6.31-611.29", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
