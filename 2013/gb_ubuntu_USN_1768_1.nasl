###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1768_1.nasl 8448 2018-01-17 16:18:06Z teissa $
#
# Ubuntu Update for linux-lts-quantal USN-1768-1
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
tag_insight = "Andrew Cooper of Citrix reported a Xen stack corruption in the Linux
  kernel. An unprivileged user in a 32bit PVOPS guest can cause the guest
  kernel to crash, or operate erroneously. (CVE-2013-0190)

  A failure to validate input was discovered in the Linux kernel's Xen
  netback (network backend) driver. A user in a guest OS may exploit this
  flaw to cause a denial of service to the guest OS and other guest domains.
  (CVE-2013-0216)
  
  A memory leak was discovered in the Linux kernel's Xen netback (network
  backend) driver. A user in a guest OS could trigger this flaw to cause a
  denial of service on the system. (CVE-2013-0217)
  
  A flaw was discovered in the Linux kernel Xen PCI backend driver. If a PCI
  device is assigned to the guest OS, the guest OS could exploit this flaw to
  cause a denial of service on the host. (CVE-2013-0231)
  
  A flaw was reported in the permission checks done by the Linux kernel for
  /dev/cpu/*/msr. A local root user with all capabilities dropped could
  exploit this flaw to execute code with full root capabilities.
  (CVE-2013-0268)
  
  Tommi Rantala discovered a flaw in the a flaw the Linux kernels handling of
  datagrams packets when the MSG_PEEK flag is specified. An unprivileged
  local user could exploit this flaw to cause a denial of service (system
  hang). (CVE-2013-0290)
  
  A flaw was discovered in the Linux kernel's vhost driver used to accelerate
  guest networking in KVM based virtual machines. A privileged guest user
  could exploit this flaw to crash the host system. (CVE-2013-0311)
  
  A flaw was discovered in the Extended Verification Module (EVM) of the
  Linux kernel. An unprivileged local user code exploit this flaw to cause a
  denial of service (system crash). (CVE-2013-0313)
  
  An information leak was discovered in the Linux kernel's Bluetooth stack
  when HIDP (Human Interface Device Protocol) support is enabled. A local
  unprivileged user could exploit this flaw to cause an information leak from
  the kernel. (CVE-2013-0349)";


tag_affected = "linux-lts-quantal on Ubuntu 12.04 LTS";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-1768-1/");
  script_id(841367);
  script_version("$Revision: 8448 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-17 17:18:06 +0100 (Wed, 17 Jan 2018) $");
  script_tag(name:"creation_date", value:"2013-03-19 09:49:48 +0530 (Tue, 19 Mar 2013)");
  script_cve_id("CVE-2013-0190", "CVE-2013-0216", "CVE-2013-0217", "CVE-2013-0231",
                "CVE-2013-0268", "CVE-2013-0290", "CVE-2013-0311", "CVE-2013-0313",
                "CVE-2013-0349");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:H/Au:S/C:C/I:C/A:C");
  script_xref(name: "USN", value: "1768-1");
  script_name("Ubuntu Update for linux-lts-quantal USN-1768-1");

  script_tag(name: "summary" , value: "Check for the Version of linux-lts-quantal");
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

  if ((res = isdpkgvuln(pkg:"linux-image-3.5.0-26-generic", ver:"3.5.0-26.42~precise1", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
