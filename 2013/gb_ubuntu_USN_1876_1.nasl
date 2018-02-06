###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1876_1.nasl 8672 2018-02-05 16:39:18Z teissa $
#
# Ubuntu Update for linux USN-1876-1
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
tag_insight = "Andrew Honig reported a flaw in the way KVM (Kernel-based Virtual Machine)
  emulated the IOAPIC. A privileged guest user could exploit this flaw to
  read host memory or cause a denial of service (crash the host).
  (CVE-2013-1798)

  An information leak was discovered in the Linux kernel's rcvmsg path for
  ATM (Asynchronous Transfer Mode). A local user could exploit this flaw to
  examine potentially sensitive information from the kernel's stack memory.
  (CVE-2013-3222)

  An information leak was discovered in the Linux kernel's recvmsg path for
  ax25 address family. A local user could exploit this flaw to examine
  potentially sensitive information from the kernel's stack memory.
  (CVE-2013-3223)

  An information leak was discovered in the Linux kernel's recvmsg path for
  the bluetooth address family. A local user could exploit this flaw to
  examine potentially sensitive information from the kernel's stack memory.
  (CVE-2013-3224)

  An information leak was discovered in the Linux kernel's bluetooth rfcomm
  protocol support. A local user could exploit this flaw to examine
  potentially sensitive information from the kernel's stack memory.
  (CVE-2013-3225)

  An information leak was discovered in the Linux kernel's IRDA (infrared)
  support subsystem. A local user could exploit this flaw to examine
  potentially sensitive information from the kernel's stack memory.
  (CVE-2013-3228)

  An information leak was discovered in the Linux kernel's s390 - z/VM
  support. A local user could exploit this flaw to examine potentially
  sensitive information from the kernel's stack memory. (CVE-2013-3229)

  An information leak was discovered in the Linux kernel's llc (Logical Link
  Layer 2) support. A local user could exploit this flaw to examine
  potentially sensitive information from the kernel's stack memory.
  (CVE-2013-3231)

  An information leak was discovered in the Linux kernel's receive message
  handling for the netrom address family. A local user could exploit this
  flaw to obtain sensitive information from the kernel's stack memory.
  (CVE-2013-3232)

  An information leak was discovered in the Linux kernel's Rose X.25 protocol
  layer. A local user could exploit this flaw to examine potentially
  sensitive information from the kernel's stack memory. (CVE-2013-3234)

  An information leak was discovered in the Linux kernel's TIPC (Transparent
  Inter Process Communication) protocol implementation. A local user could
  exploit this flaw to examine potentially sensitive information from the
  kernel's stack memory. (CVE-2013-3235)";


tag_affected = "linux on Ubuntu 10.04 LTS";
tag_solution = "Please Install the Updated Packages.";

if(description)
{
  script_id(841475);
  script_version("$Revision: 8672 $");
  script_tag(name:"last_modification", value:"$Date: 2018-02-05 17:39:18 +0100 (Mon, 05 Feb 2018) $");
  script_tag(name:"creation_date", value:"2013-06-18 10:41:44 +0530 (Tue, 18 Jun 2013)");
  script_cve_id("CVE-2013-1798", "CVE-2013-3222", "CVE-2013-3223", "CVE-2013-3224",
                "CVE-2013-3225", "CVE-2013-3228", "CVE-2013-3229", "CVE-2013-3231",
                "CVE-2013-3232", "CVE-2013-3234", "CVE-2013-3235");
  script_tag(name:"cvss_base", value:"6.2");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:H/Au:N/C:C/I:N/A:C");
  script_name("Ubuntu Update for linux USN-1876-1");

  script_xref(name: "USN", value: "1876-1");
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-1876-1/");
  script_tag(name: "summary" , value: "Check for the Version of linux");
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

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.32-48-386", ver:"2.6.32-48.110", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.32-48-generic", ver:"2.6.32-48.110", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.32-48-generic-pae", ver:"2.6.32-48.110", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.32-48-ia64", ver:"2.6.32-48.110", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.32-48-lpia", ver:"2.6.32-48.110", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.32-48-powerpc", ver:"2.6.32-48.110", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.32-48-powerpc-smp", ver:"2.6.32-48.110", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.32-48-powerpc64-smp", ver:"2.6.32-48.110", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.32-48-preempt", ver:"2.6.32-48.110", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.32-48-server", ver:"2.6.32-48.110", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.32-48-sparc64", ver:"2.6.32-48.110", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.32-48-sparc64-smp", ver:"2.6.32-48.110", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.32-48-versatile", ver:"2.6.32-48.110", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.32-48-virtual", ver:"2.6.32-48.110", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
