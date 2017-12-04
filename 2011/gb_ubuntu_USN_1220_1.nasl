###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1220_1.nasl 7964 2017-12-01 07:32:11Z santu $
#
# Ubuntu Update for linux-ti-omap4 USN-1220-1
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
tag_insight = "Ryan Sweat discovered that the kernel incorrectly handled certain VLAN
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
  
  Dan Rosenberg discovered that the Bluetooth stack incorrectly handled
  certain L2CAP requests. If a system was using Bluetooth, a remote attacker
  could send specially crafted traffic to crash the system or gain root
  privileges. (CVE-2011-2497)
  
  Mauro Carvalho Chehab discovered that the si4713 radio driver did not
  correctly check the length of memory copies. If this hardware was
  available, a local attacker could exploit this to crash the system or gain
  root privileges. (CVE-2011-2700)
  
  Herbert Xu discovered that certain fields were incorrectly handled when
  Generic Receive Offload (CVE-2011-2723)
  
  Time Warns discovered that long symlinks were incorrectly handled on Be
  filesystems. A local attacker could exploit this with a malformed Be
  filesystem and crash the system, leading to a denial of service.
  (CVE-2011-2928)
  
  Dan Kaminsky discovered that the kernel incorrectly handled random sequence
  number generation. An attacker could use this flaw to possibly predict
  sequence numbers and inject packets. (CVE-2011-3188)
  
  Darren Lavender discovered that the CIFS client incorrectly handled certain
  large values. A remote attacker with a malicious server could exploit this
  to crash the system or possibly execute arbitrary code as the root user.
  (CVE-2011-3191)";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-1220-1";
tag_affected = "linux-ti-omap4 on Ubuntu 10.10";
tag_solution = "Please Install the Updated Packages.";


if(description)
{
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-1220-1/");
  script_id(840758);
  script_version("$Revision: 7964 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 08:32:11 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2011-09-30 16:02:57 +0200 (Fri, 30 Sep 2011)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name: "USN", value: "1220-1");
  script_cve_id("CVE-2011-1576", "CVE-2011-1776", "CVE-2011-2213", "CVE-2011-2497", "CVE-2011-2700", "CVE-2011-2723", "CVE-2011-2928", "CVE-2011-3188", "CVE-2011-3191");
  script_name("Ubuntu Update for linux-ti-omap4 USN-1220-1");

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

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.35-903-omap4", ver:"2.6.35-903.25", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
