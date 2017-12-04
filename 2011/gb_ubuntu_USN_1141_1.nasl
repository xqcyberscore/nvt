###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1141_1.nasl 7964 2017-12-01 07:32:11Z santu $
#
# Ubuntu Update for linux USN-1141-1
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
tag_insight = "Brad Spengler discovered that the kernel did not correctly account for
  userspace memory allocations during exec() calls. A local attacker could
  exploit this to consume all system memory, leading to a denial of service.
  (CVE-2010-4243)

  Alexander Duyck discovered that the Intel Gigabit Ethernet driver did not
  correctly handle certain configurations. If such a device was configured
  without VLANs, a remote attacker could crash the system, leading to a
  denial of service. (CVE-2010-4263)
  
  Nelson Elhage discovered that Econet did not correctly handle AUN packets
  over UDP. A local attacker could send specially crafted traffic to crash
  the system, leading to a denial of service. (CVE-2010-4342)
  
  Dan Rosenberg discovered that IRDA did not correctly check the size of
  buffers. On non-x86 systems, a local attacker could exploit this to read
  kernel heap memory, leading to a loss of privacy. (CVE-2010-4529)
  
  Dan Rosenburg discovered that the CAN subsystem leaked kernel addresses
  into the /proc filesystem. A local attacker could use this to increase
  the chances of a successful memory corruption exploit. (CVE-2010-4565)
  
  Kees Cook discovered that the IOWarrior USB device driver did not
  correctly check certain size fields. A local attacker with physical
  access could plug in a specially crafted USB device to crash the system
  or potentially gain root privileges. (CVE-2010-4656)
  
  Goldwyn Rodrigues discovered that the OCFS2 filesystem did not correctly
  clear memory when writing certain file holes. A local attacker could
  exploit this to read uninitialized data from the disk, leading to a loss
  of privacy. (CVE-2011-0463)
  
  Dan Carpenter discovered that the TTPCI DVB driver did not check certain
  values during an ioctl. If the dvb-ttpci module was loaded, a local
  attacker could exploit this to crash the system, leading to a denial of
  service, or possibly gain root privileges. (CVE-2011-0521)
  
  Jens Kuehnel discovered that the InfiniBand driver contained a race
  condition. On systems using InfiniBand, a local attacker could send
  specially crafted requests to crash the system, leading to a denial of
  service. (CVE-2011-0695)
  
  Rafael Dominguez Vega discovered that the caiaq Native Instruments USB
  driver did not correctly validate string lengths. A local attacker with
  physical access could plug in a specially crafted USB device to crash
  the system or potentially gain root privileges. (CVE-2011-0712)
  
  Kees Cook reported that /proc/pid/stat did not correctly filter certain
  memory locations. A local attacker could determine the mem ... 

  Description truncated, for more information please check the Reference URL";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-1141-1";
tag_affected = "linux on Ubuntu 10.04 LTS";
tag_solution = "Please Install the Updated Packages.";


if(description)
{
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-1141-1/");
  script_id(840671);
  script_version("$Revision: 7964 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 08:32:11 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2011-06-06 16:56:27 +0200 (Mon, 06 Jun 2011)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name: "USN", value: "1141-1");
  script_cve_id("CVE-2010-4243", "CVE-2010-4263", "CVE-2010-4342", "CVE-2010-4529", "CVE-2010-4565", "CVE-2010-4656", "CVE-2011-0463", "CVE-2011-0521", "CVE-2011-0695", "CVE-2011-0712", "CVE-2011-0726", "CVE-2011-1010", "CVE-2011-1012", "CVE-2011-1013", "CVE-2011-1016", "CVE-2011-1019", "CVE-2011-1082", "CVE-2011-1083", "CVE-2011-1182");
  script_name("Ubuntu Update for linux USN-1141-1");

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

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.32-316-ec2", ver:"2.6.32-316.31", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.32-32-386", ver:"2.6.32-32.62", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.32-32-generic", ver:"2.6.32-32.62", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.32-32-generic-pae", ver:"2.6.32-32.62", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.32-32-ia64", ver:"2.6.32-32.62", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.32-32-lpia", ver:"2.6.32-32.62", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.32-32-powerpc", ver:"2.6.32-32.62", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.32-32-powerpc-smp", ver:"2.6.32-32.62", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.32-32-powerpc64-smp", ver:"2.6.32-32.62", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.32-32-preempt", ver:"2.6.32-32.62", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.32-32-server", ver:"2.6.32-32.62", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.32-32-sparc64", ver:"2.6.32-32.62", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.32-32-sparc64-smp", ver:"2.6.32-32.62", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.32-32-versatile", ver:"2.6.32-32.62", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.32-32-virtual", ver:"2.6.32-32.62", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
