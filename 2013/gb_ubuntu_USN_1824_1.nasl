###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1824_1.nasl 7958 2017-12-01 06:47:47Z santu $
#
# Ubuntu Update for linux USN-1824-1
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
tag_insight = "Mathias Krause discovered an information leak in the Linux kernel's ISO
  9660 CDROM file system driver. A local user could exploit this flaw to
  examine some of the kernel's heap memory. (CVE-2012-6549)

  Mathias Krause discovered a flaw in xfrm_user in the Linux kernel. A local
  attacker with NET_ADMIN capability could potentially exploit this flaw to
  escalate privileges. (CVE-2013-1826)

  A buffer overflow was discovered in the Linux Kernel's USB subsystem for
  devices reporting the cdc-wdm class. A specially crafted USB device when
  plugged-in could cause a denial of service (system crash) or possibly
  execute arbitrary code. (CVE-2013-1860)

  An information leak was discovered in the Linux kernel's /dev/dvb device. A
  local user could exploit this flaw to obtain sensitive information from the
  kernel's stack memory. (CVE-2013-1928)

  An information leak in the Linux kernel's dcb netlink interface was
  discovered. A local user could obtain sensitive information by examining
  kernel stack memory. (CVE-2013-2634)";


tag_affected = "linux on Ubuntu 10.04 LTS";
tag_solution = "Please Install the Updated Packages.";

if(description)
{
  script_id(841430);
  script_version("$Revision: 7958 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 07:47:47 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2013-05-17 09:55:56 +0530 (Fri, 17 May 2013)");
  script_cve_id("CVE-2012-6549", "CVE-2013-1826", "CVE-2013-1860", "CVE-2013-1928",
                "CVE-2013-2634");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Ubuntu Update for linux USN-1824-1");

  script_xref(name: "USN", value: "1824-1");
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-1824-1/");
  script_summary("Check for the Version of linux");
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

if(release == "UBUNTU10.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.32-47-386", ver:"2.6.32-47.109", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.32-47-generic", ver:"2.6.32-47.109", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.32-47-generic-pae", ver:"2.6.32-47.109", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.32-47-ia64", ver:"2.6.32-47.109", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.32-47-lpia", ver:"2.6.32-47.109", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.32-47-powerpc", ver:"2.6.32-47.109", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.32-47-powerpc-smp", ver:"2.6.32-47.109", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.32-47-powerpc64-smp", ver:"2.6.32-47.109", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.32-47-preempt", ver:"2.6.32-47.109", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.32-47-server", ver:"2.6.32-47.109", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.32-47-sparc64", ver:"2.6.32-47.109", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.32-47-sparc64-smp", ver:"2.6.32-47.109", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.32-47-versatile", ver:"2.6.32-47.109", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.32-47-virtual", ver:"2.6.32-47.109", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
