###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1781_1.nasl 7958 2017-12-01 06:47:47Z santu $
#
# Ubuntu Update for linux-ti-omap4 USN-1781-1
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
tag_insight = "Andrew Jones discovered a flaw with the xen_iret function in Linux kernel's
  Xen virtualizeation. In the 32-bit Xen paravirt platform an unprivileged
  guest OS user could exploit this flaw to cause a denial of service (crash
  the system) or gain guest OS privilege. (CVE-2013-0228)

  A flaw was reported in the permission checks done by the Linux kernel for
  /dev/cpu/*/msr. A local root user with all capabilities dropped could
  exploit this flaw to execute code with full root capabilities.
  (CVE-2013-0268)
  
  A flaw was discovered in the Linux kernel's vhost driver used to accelerate
  guest networking in KVM based virtual machines. A privileged guest user
  could exploit this flaw to crash the host system. (CVE-2013-0311)
  
  A flaw was discovered in the Extended Verification Module (EVM) of the
  Linux kernel. An unprivileged local user code exploit this flaw to cause a
  denial of service (system crash). (CVE-2013-0313)
  
  An information leak was discovered in the Linux kernel's Bluetooth stack
  when HIDP (Human Interface Device Protocol) support is enabled. A local
  unprivileged user could exploit this flaw to cause an information leak from
  the kernel. (CVE-2013-0349)
  
  A flaw was discovered in the Edgeort USB serial converter driver when the
  device is disconnected while it is in use. A local user could exploit this
  flaw to cause a denial of service (system crash). (CVE-2013-1774)";


tag_affected = "linux-ti-omap4 on Ubuntu 12.04 LTS";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-1781-1/");
  script_id(841376);
  script_version("$Revision: 7958 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 07:47:47 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2013-03-28 09:50:13 +0530 (Thu, 28 Mar 2013)");
  script_cve_id("CVE-2013-0228", "CVE-2013-0268", "CVE-2013-0311", "CVE-2013-0313", "CVE-2013-0349", "CVE-2013-1774");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:H/Au:S/C:C/I:C/A:C");
  script_xref(name: "USN", value: "1781-1");
  script_name("Ubuntu Update for linux-ti-omap4 USN-1781-1");

  script_summary("Check for the Version of linux-ti-omap4");
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

  if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-1427-omap4", ver:"3.2.0-1427.36", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
