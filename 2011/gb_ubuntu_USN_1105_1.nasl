###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1105_1.nasl 7964 2017-12-01 07:32:11Z santu $
#
# Ubuntu Update for linux vulnerabilities USN-1105-1
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
  (CVE-2010-4075, CVE-2010-4076, CVE-2010-4077)

  Dan Rosenberg discovered that the socket filters did not correctly
  initialize structure memory. A local attacker could create malicious
  filters to read portions of kernel stack memory, leading to a loss of
  privacy. (CVE-2010-4158)
  
  Dan Rosenberg discovered that certain iovec operations did not calculate
  page counts correctly. A local attacker could exploit this to crash the
  system, leading to a denial of service. (CVE-2010-4162)
  
  Dan Rosenberg discovered that the SCSI subsystem did not correctly validate
  iov segments. A local attacker with access to a SCSI device could send
  specially crafted requests to crash the system, leading to a denial of
  service. (CVE-2010-4163)
  
  Dan Rosenberg discovered multiple flaws in the X.25 facilities parsing.
  If a system was using X.25, a remote attacker could exploit this to
  crash the system, leading to a denial of service. (CVE-2010-4164)
  
  Alan Cox discovered that the HCI UART driver did not correctly check if a
  write operation was available. A local attacker could exploit this flaw to
  gain root privileges. (CVE-2010-4242)
  
  Nelson Elhage discovered that the kernel did not correctly handle process
  cleanup after triggering a recoverable kernel bug. If a local attacker
  were able to trigger certain kinds of kernel bugs, they could create a
  specially crafted process to gain root privileges. (CVE-2010-4258)
  
  Tavis Ormandy discovered that the install_special_mapping function could
  bypass the mmap_min_addr restriction. A local attacker could exploit this
  to mmap 4096 bytes below the mmap_min_addr area, possibly improving the
  chances of performing NULL pointer dereference attacks. (CVE-2010-4346)";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-1105-1";
tag_affected = "linux vulnerabilities on Ubuntu 8.04 LTS";
tag_solution = "Please Install the Updated Packages.";


if(description)
{
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-1105-1/");
  script_id(840632);
  script_version("$Revision: 7964 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 08:32:11 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2011-04-11 15:05:25 +0200 (Mon, 11 Apr 2011)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_xref(name: "USN", value: "1105-1");
  script_cve_id("CVE-2010-4075", "CVE-2010-4076", "CVE-2010-4077", "CVE-2010-4158", "CVE-2010-4162", "CVE-2010-4163", "CVE-2010-4164", "CVE-2010-4242", "CVE-2010-4258", "CVE-2010-4346");
  script_name("Ubuntu Update for linux vulnerabilities USN-1105-1");

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

if(release == "UBUNTU8.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"linux-headers-2.6.24-29-386", ver:"2.6.24-29.88", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-headers-2.6.24-29-generic", ver:"2.6.24-29.88", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-headers-2.6.24-29-openvz", ver:"2.6.24-29.88", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-headers-2.6.24-29-rt", ver:"2.6.24-29.88", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-headers-2.6.24-29-server", ver:"2.6.24-29.88", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-headers-2.6.24-29-virtual", ver:"2.6.24-29.88", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-headers-2.6.24-29-xen", ver:"2.6.24-29.88", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.24-29-386", ver:"2.6.24-29.88", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.24-29-generic", ver:"2.6.24-29.88", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.24-29-openvz", ver:"2.6.24-29.88", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.24-29-rt", ver:"2.6.24-29.88", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.24-29-server", ver:"2.6.24-29.88", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.24-29-virtual", ver:"2.6.24-29.88", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.24-29-xen", ver:"2.6.24-29.88", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-debug-2.6.24-29-386", ver:"2.6.24-29.88", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-debug-2.6.24-29-generic", ver:"2.6.24-29.88", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-debug-2.6.24-29-server", ver:"2.6.24-29.88", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-debug-2.6.24-29-virtual", ver:"2.6.24-29.88", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-libc-dev", ver:"2.6.24-29.88", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-doc-2.6.24", ver:"2.6.24-29.88", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-headers-2.6.24-29", ver:"2.6.24-29.88", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-kernel-devel", ver:"2.6.24-29.88", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-source-2.6.24", ver:"2.6.24-29.88", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"acpi-modules-2.6.24-29-386-di", ver:"2.6.24-29.88", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"acpi-modules-2.6.24-29-generic-di", ver:"2.6.24-29.88", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"block-modules-2.6.24-29-386-di", ver:"2.6.24-29.88", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"block-modules-2.6.24-29-generic-di", ver:"2.6.24-29.88", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"crypto-modules-2.6.24-29-386-di", ver:"2.6.24-29.88", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"crypto-modules-2.6.24-29-generic-di", ver:"2.6.24-29.88", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"fat-modules-2.6.24-29-386-di", ver:"2.6.24-29.88", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"fat-modules-2.6.24-29-generic-di", ver:"2.6.24-29.88", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"fb-modules-2.6.24-29-386-di", ver:"2.6.24-29.88", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"fb-modules-2.6.24-29-generic-di", ver:"2.6.24-29.88", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firewire-core-modules-2.6.24-29-386-di", ver:"2.6.24-29.88", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firewire-core-modules-2.6.24-29-generic-di", ver:"2.6.24-29.88", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"floppy-modules-2.6.24-29-386-di", ver:"2.6.24-29.88", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"floppy-modules-2.6.24-29-generic-di", ver:"2.6.24-29.88", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"fs-core-modules-2.6.24-29-386-di", ver:"2.6.24-29.88", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"fs-core-modules-2.6.24-29-generic-di", ver:"2.6.24-29.88", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"fs-secondary-modules-2.6.24-29-386-di", ver:"2.6.24-29.88", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"fs-secondary-modules-2.6.24-29-generic-di", ver:"2.6.24-29.88", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"ide-modules-2.6.24-29-386-di", ver:"2.6.24-29.88", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"ide-modules-2.6.24-29-generic-di", ver:"2.6.24-29.88", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"input-modules-2.6.24-29-386-di", ver:"2.6.24-29.88", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"input-modules-2.6.24-29-generic-di", ver:"2.6.24-29.88", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"ipv6-modules-2.6.24-29-386-di", ver:"2.6.24-29.88", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"ipv6-modules-2.6.24-29-generic-di", ver:"2.6.24-29.88", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"irda-modules-2.6.24-29-386-di", ver:"2.6.24-29.88", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"irda-modules-2.6.24-29-generic-di", ver:"2.6.24-29.88", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"kernel-image-2.6.24-29-386-di", ver:"2.6.24-29.88", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"kernel-image-2.6.24-29-generic-di", ver:"2.6.24-29.88", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"md-modules-2.6.24-29-386-di", ver:"2.6.24-29.88", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"md-modules-2.6.24-29-generic-di", ver:"2.6.24-29.88", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"message-modules-2.6.24-29-386-di", ver:"2.6.24-29.88", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"message-modules-2.6.24-29-generic-di", ver:"2.6.24-29.88", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"nfs-modules-2.6.24-29-386-di", ver:"2.6.24-29.88", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"nfs-modules-2.6.24-29-generic-di", ver:"2.6.24-29.88", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"nic-modules-2.6.24-29-386-di", ver:"2.6.24-29.88", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"nic-modules-2.6.24-29-generic-di", ver:"2.6.24-29.88", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"nic-pcmcia-modules-2.6.24-29-386-di", ver:"2.6.24-29.88", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"nic-pcmcia-modules-2.6.24-29-generic-di", ver:"2.6.24-29.88", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"nic-shared-modules-2.6.24-29-386-di", ver:"2.6.24-29.88", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"nic-shared-modules-2.6.24-29-generic-di", ver:"2.6.24-29.88", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"nic-usb-modules-2.6.24-29-386-di", ver:"2.6.24-29.88", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"nic-usb-modules-2.6.24-29-generic-di", ver:"2.6.24-29.88", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"parport-modules-2.6.24-29-386-di", ver:"2.6.24-29.88", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"parport-modules-2.6.24-29-generic-di", ver:"2.6.24-29.88", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"pata-modules-2.6.24-29-386-di", ver:"2.6.24-29.88", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"pata-modules-2.6.24-29-generic-di", ver:"2.6.24-29.88", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"pcmcia-modules-2.6.24-29-386-di", ver:"2.6.24-29.88", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"pcmcia-modules-2.6.24-29-generic-di", ver:"2.6.24-29.88", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"pcmcia-storage-modules-2.6.24-29-386-di", ver:"2.6.24-29.88", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"pcmcia-storage-modules-2.6.24-29-generic-di", ver:"2.6.24-29.88", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"plip-modules-2.6.24-29-386-di", ver:"2.6.24-29.88", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"plip-modules-2.6.24-29-generic-di", ver:"2.6.24-29.88", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"ppp-modules-2.6.24-29-386-di", ver:"2.6.24-29.88", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"ppp-modules-2.6.24-29-generic-di", ver:"2.6.24-29.88", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"sata-modules-2.6.24-29-386-di", ver:"2.6.24-29.88", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"sata-modules-2.6.24-29-generic-di", ver:"2.6.24-29.88", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"scsi-modules-2.6.24-29-386-di", ver:"2.6.24-29.88", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"scsi-modules-2.6.24-29-generic-di", ver:"2.6.24-29.88", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"serial-modules-2.6.24-29-386-di", ver:"2.6.24-29.88", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"serial-modules-2.6.24-29-generic-di", ver:"2.6.24-29.88", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"socket-modules-2.6.24-29-386-di", ver:"2.6.24-29.88", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"socket-modules-2.6.24-29-generic-di", ver:"2.6.24-29.88", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"storage-core-modules-2.6.24-29-386-di", ver:"2.6.24-29.88", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"storage-core-modules-2.6.24-29-generic-di", ver:"2.6.24-29.88", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"usb-modules-2.6.24-29-386-di", ver:"2.6.24-29.88", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"usb-modules-2.6.24-29-generic-di", ver:"2.6.24-29.88", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
