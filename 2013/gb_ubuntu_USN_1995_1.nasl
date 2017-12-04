###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1995_1.nasl 7958 2017-12-01 06:47:47Z santu $
#
# Ubuntu Update for linux-lts-raring USN-1995-1
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

if(description)
{
  script_id(841602);
  script_version("$Revision: 7958 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 07:47:47 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2013-10-29 16:32:47 +0530 (Tue, 29 Oct 2013)");
  script_cve_id("CVE-2013-2237", "CVE-2013-2888", "CVE-2013-2892", "CVE-2013-2896", "CVE-2013-2898", "CVE-2013-2899", "CVE-2013-4300");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Ubuntu Update for linux-lts-raring USN-1995-1");

  tag_insight = "An information leak was discovered in the Linux kernel when reading
broadcast messages from the notify_policy interface of the IPSec
key_socket. A local user could exploit this flaw to examine potentially
sensitive information in kernel memory. (CVE-2013-2237)

Kees Cook discovered flaw in the Human Interface Device (HID) subsystem of
the Linux kernel. A physically proximate attacker could exploit this flaw
to execute arbitrary code or cause a denial of service (heap memory
corruption) via a specially crafted device that provides an invalid Report
ID. (CVE-2013-2888)

Kees Cook discovered a flaw in the Human Interface Device (HID) subsystem
of the Linux kernel when CONFIG_HID_PANTHERLORD is enabled. A physically
proximate attacker could cause a denial of service (heap out-of-bounds
write) via a specially crafted device. (CVE-2013-2892)

Kees Cook discovered a vulnerability in the Linux Kernel's Human Interface
Device (HID) subsystem's support for N-Trig touch screens. A physically
proximate attacker could exploit this flaw to cause a denial of service
(OOPS) via a specially crafted device. (CVE-2013-2896)

Kees Cook discovered an information leak in the Linux kernel's Human
Interface Device (HID) subsystem when CONFIG_HID_SENSOR_HUB is enabled. A
physically proximate attacker could obtain potentially sensitive
information from kernel memory via a specially crafted device.
(CVE-2013-2898)

Kees Cook discovered a flaw in the Human Interface Device (HID) subsystem
of the Linux kernel whe CONFIG_HID_PICOLCD is enabled. A physically
proximate attacker could exploit this flaw to cause a denial of service
(OOPS) via a specially crafted device. (CVE-2013-2899)

A flaw was discovered in how the Linux Kernel's networking stack checks scm
credentials when used with namespaces. A local attacker could exploit this
flaw to gain privileges. (CVE-2013-4300)";

  tag_affected = "linux-lts-raring on Ubuntu 12.04 LTS";

  tag_solution = "Please Install the Updated Packages.";


  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name: "USN", value: "1995-1");
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-1995-1/");
  script_summary("Check for the Version of linux-lts-raring");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
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

  if ((res = isdpkgvuln(pkg:"linux-image-3.8.0-32-generic", ver:"3.8.0-32.47~precise1", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}