###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_2038_1.nasl 7958 2017-12-01 06:47:47Z santu $
#
# Ubuntu Update for linux USN-2038-1
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_id(841647);
  script_version("$Revision: 7958 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 07:47:47 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2013-12-04 10:29:02 +0530 (Wed, 04 Dec 2013)");
  script_cve_id("CVE-2013-0343", "CVE-2013-2140", "CVE-2013-2888", "CVE-2013-2889",
                "CVE-2013-2892", "CVE-2013-2893", "CVE-2013-2895", "CVE-2013-2896",
                "CVE-2013-2897", "CVE-2013-2899", "CVE-2013-4350", "CVE-2013-4387");
  script_tag(name:"cvss_base", value:"6.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:C/I:C/A:C");
  script_name("Ubuntu Update for linux USN-2038-1");

  tag_insight = "An information leak was discovered in the handling of ICMPv6
Router Advertisement (RA) messages in the Linux kernel's IPv6 network stack. A
remote attacker could exploit this flaw to cause a denial of service
(excessive retries and address-generation outage), and consequently obtain
sensitive information. (CVE-2013-0343)

A flaw was discovered in the Xen subsystem of the Linux kernel when it
provides read-only access to a disk that supports TRIM or SCSI UNMAP to a
guest OS. A privileged user in the guest OS could exploit this flaw to
destroy data on the disk, even though the guest OS should not be able to
write to the disk. (CVE-2013-2140)

Kees Cook discovered flaw in the Human Interface Device (HID) subsystem of
the Linux kernel. A physically proximate attacker could exploit this flaw
to execute arbitrary code or cause a denial of service (heap memory
corruption) via a specially crafted device that provides an invalid Report
ID. (CVE-2013-2888)

Kees Cook discovered flaw in the Human Interface Device (HID) subsystem
when CONFIG_HID_ZEROPLUS is enabled. A physically proximate attacker could
leverage this flaw to cause a denial of service via a specially crafted
device. (CVE-2013-2889)

Kees Cook discovered a flaw in the Human Interface Device (HID) subsystem
of the Linux kerenl when CONFIG_HID_PANTHERLORD is enabled. A physically
proximate attacker could cause a denial of service (heap out-of-bounds
write) via a specially crafted device. (CVE-2013-2892)

Kees Cook discovered another flaw in the Human Interface Device (HID)
subsystem of the Linux kernel when any of CONFIG_LOGITECH_FF,
CONFIG_LOGIG940_FF, or CONFIG_LOGIWHEELS_FF are enabled. A physcially
proximate attacker can leverage this flaw to cause a denial of service vias
a specially crafted device. (CVE-2013-2893)

Kees Cook discovered another flaw in the Human Interface Device (HID)
subsystem of the Linux kernel when CONFIG_HID_LOGITECH_DJ is enabled. A
physically proximate attacker could cause a denial of service (OOPS) or
obtain sensitive information from kernel memory via a specially crafted
device. (CVE-2013-2895)

Kees Cook discovered a vulnerability in the Linux Kernel's Human Interface
Device (HID) subsystem's support for N-Trig touch screens. A physically
proximate attacker could exploit this flaw to cause a denial of service
(OOPS) via a specially crafted device. (CVE-2013-2896)

Kees Cook discovered yet another flaw in the Human Interface Device (HID)
subsystem of the Linux kernel when CONFIG_HID_MULTITOUCH is enabled. A
physically proximate attacker could leverage this flaw to cause a denial of
service (OOPS) via a specia ...

  Description truncated, for more information please check the Reference URL";

  tag_affected = "linux on Ubuntu 12.04 LTS";

  tag_solution = "Please Install the Updated Packages.";


  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name: "USN", value: "2038-1");
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-2038-1/");
  script_summary("Check for the Version of linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages");
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

  if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-57-generic", ver:"3.2.0-57.87", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-57-generic-pae", ver:"3.2.0-57.87", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-57-highbank", ver:"3.2.0-57.87", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-57-omap", ver:"3.2.0-57.87", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-57-powerpc-smp", ver:"3.2.0-57.87", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-57-powerpc64-smp", ver:"3.2.0-57.87", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-57-virtual", ver:"3.2.0-57.87", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
