###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_2182_1.nasl 7957 2017-12-01 06:40:08Z santu $
#
# Ubuntu Update for qemu USN-2182-1
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_id(841795);
  script_version("$Revision: 7957 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 07:40:08 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2014-05-05 11:24:14 +0530 (Mon, 05 May 2014)");
  script_cve_id("CVE-2013-4544", "CVE-2014-0150", "CVE-2014-2894");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Ubuntu Update for qemu USN-2182-1");

  tag_insight = "Michael S. Tsirkin discovered that QEMU incorrectly handled
vmxnet3 devices. A local guest could possibly use this issue to cause a denial
of service, or possibly execute arbitrary code on the host. This issue only
applied to Ubuntu 13.10 and Ubuntu 14.04 LTS. (CVE-2013-4544)

Michael S. Tsirkin discovered that QEMU incorrectly handled virtio-net
MAC addresses. A local guest could possibly use this issue to cause a
denial of service, or possibly execute arbitrary code on the host.
(CVE-2014-0150)

Beno&#238 t Canet discovered that QEMU incorrectly handled SMART self-tests. A
local guest could possibly use this issue to cause a denial of service, or
possibly execute arbitrary code on the host. (CVE-2014-2894)";

  tag_affected = "qemu on Ubuntu 14.04 LTS ,
  Ubuntu 13.10 ,
  Ubuntu 12.10 ,
  Ubuntu 12.04 LTS ,
  Ubuntu 10.04 LTS";

  tag_solution = "Please Install the Updated Packages.";


  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name: "USN", value: "2182-1");
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-2182-1/");
  script_summary("Check for the Version of qemu");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
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

if(release == "UBUNTU14.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"qemu-system", ver:"2.0.0~rc1+dfsg-0ubuntu3.1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"qemu-system-aarch64", ver:"2.0.0~rc1+dfsg-0ubuntu3.1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"qemu-system-arm", ver:"2.0.0~rc1+dfsg-0ubuntu3.1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"qemu-system-mips", ver:"2.0.0~rc1+dfsg-0ubuntu3.1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"qemu-system-misc", ver:"2.0.0~rc1+dfsg-0ubuntu3.1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"qemu-system-ppc", ver:"2.0.0~rc1+dfsg-0ubuntu3.1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"qemu-system-sparc", ver:"2.0.0~rc1+dfsg-0ubuntu3.1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"qemu-system-x86", ver:"2.0.0~rc1+dfsg-0ubuntu3.1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU12.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"qemu-kvm", ver:"1.0+noroms-0ubuntu14.14", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU10.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"qemu-kvm", ver:"0.12.3+noroms-0ubuntu9.22", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU13.10")
{

  if ((res = isdpkgvuln(pkg:"qemu-system", ver:"1.5.0+dfsg-3ubuntu5.4", rls:"UBUNTU13.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"qemu-system-arm", ver:"1.5.0+dfsg-3ubuntu5.4", rls:"UBUNTU13.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"qemu-system-mips", ver:"1.5.0+dfsg-3ubuntu5.4", rls:"UBUNTU13.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"qemu-system-misc", ver:"1.5.0+dfsg-3ubuntu5.4", rls:"UBUNTU13.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"qemu-system-ppc", ver:"1.5.0+dfsg-3ubuntu5.4", rls:"UBUNTU13.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"qemu-system-sparc", ver:"1.5.0+dfsg-3ubuntu5.4", rls:"UBUNTU13.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"qemu-system-x86", ver:"1.5.0+dfsg-3ubuntu5.4", rls:"UBUNTU13.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU12.10")
{

  if ((res = isdpkgvuln(pkg:"qemu-kvm", ver:"1.2.0+noroms-0ubuntu2.12.10.7", rls:"UBUNTU12.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
