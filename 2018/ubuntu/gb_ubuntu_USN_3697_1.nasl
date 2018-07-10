###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_3697_1.nasl 10424 2018-07-05 14:01:21Z cfischer $
#
# Ubuntu Update for linux USN-3697-1
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843574");
  script_version("$Revision: 10424 $");
  script_tag(name:"last_modification", value:"$Date: 2018-07-05 16:01:21 +0200 (Thu, 05 Jul 2018) $");
  script_tag(name:"creation_date", value:"2018-07-03 05:47:21 +0200 (Tue, 03 Jul 2018)");
  script_cve_id("CVE-2018-1130", "CVE-2018-11508", "CVE-2018-5750", "CVE-2018-5803", 
                "CVE-2018-6927", "CVE-2018-7755", "CVE-2018-7757"); 
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("Ubuntu Update for linux USN-3697-1");
  script_tag(name:"summary", value:"Check the version of linux");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"It was discovered that a null pointer dereference vulnerability existed in
the DCCP protocol implementation in the Linux kernel. A local attacker
could use this to cause a denial of service (system crash). (CVE-2018-1130)

Jann Horn discovered that the 32 bit adjtimex() syscall implementation for
64 bit Linux kernels did not properly initialize memory returned to user
space in some situations. A local attacker could use this to expose
sensitive information (kernel memory). (CVE-2018-11508)

Wang Qize discovered that an information disclosure vulnerability existed
in the SMBus driver for ACPI Embedded Controllers in the Linux kernel. A
local attacker could use this to expose sensitive information (kernel
pointer addresses). (CVE-2018-5750)

It was discovered that the SCTP Protocol implementation in the Linux kernel
did not properly validate userspace provided payload lengths in some
situations. A local attacker could use this to cause a denial of service
(system crash). (CVE-2018-5803)

It was discovered that an integer overflow error existed in the futex
implementation in the Linux kernel. A local attacker could use this to
cause a denial of service (system crash). (CVE-2018-6927)

It was discovered that an information leak vulnerability existed in the
floppy driver in the Linux kernel. A local attacker could use this to
expose sensitive information (kernel memory). (CVE-2018-7755)

It was discovered that a memory leak existed in the SAS driver subsystem of
the Linux kernel. A local attacker could use this to cause a denial of
service (memory exhaustion). (CVE-2018-7757)");
  script_tag(name:"affected", value:"linux on Ubuntu 17.10");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"USN", value:"3697-1");
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-3697-1/");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU17\.10");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = get_kb_item("ssh/login/release");

res = "";
if(release == NULL){
  exit(0);
}

if(release == "UBUNTU17.10")
{

  if ((res = isdpkgvuln(pkg:"linux-image-4.13.0-1023-raspi2", ver:"4.13.0-1023.24", rls:"UBUNTU17.10", remove_arch:TRUE )) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-4.13.0-46-generic", ver:"4.13.0-46.51", rls:"UBUNTU17.10", remove_arch:TRUE )) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-4.13.0-46-generic-lpae", ver:"4.13.0-46.51", rls:"UBUNTU17.10", remove_arch:TRUE )) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-4.13.0-46-lowlatency", ver:"4.13.0-46.51", rls:"UBUNTU17.10", remove_arch:TRUE )) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-generic", ver:"4.13.0.46.49", rls:"UBUNTU17.10", remove_arch:TRUE )) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-generic-lpae", ver:"4.13.0.46.49", rls:"UBUNTU17.10", remove_arch:TRUE )) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-lowlatency", ver:"4.13.0.46.49", rls:"UBUNTU17.10", remove_arch:TRUE )) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-raspi2", ver:"4.13.0.1023.21", rls:"UBUNTU17.10", remove_arch:TRUE )) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
