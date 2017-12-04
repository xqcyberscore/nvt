###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1165_1.nasl 7964 2017-12-01 07:32:11Z santu $
#
# Ubuntu Update for qemu-kvm USN-1165-1
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
tag_insight = "Nelson Elhage discoverd that QEMU did not properly validate certain
  virtqueue requests from the guest. An attacker could exploit this to cause
  a denial of service of the guest or possibly execute code with the
  privileges of the user invoking the program. (CVE-2011-2212)

  Stefan Hajnoczi discovered that QEMU did not properly perform integer
  comparisons when performing virtqueue input validation. An attacker could
  exploit this to cause a denial of service of the guest or possibly execute
  code with the privileges of the user invoking the program. (CVE-2011-2512)
  
  When using QEMU with libvirt or virtualization management software based on
  libvirt such as Eucalyptus and OpenStack, QEMU guests are individually
  isolated by an AppArmor profile by default in Ubuntu.";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-1165-1";
tag_affected = "qemu-kvm on Ubuntu 11.04 ,
  Ubuntu 10.10 ,
  Ubuntu 10.04 LTS";
tag_solution = "Please Install the Updated Packages.";


if(description)
{
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-1165-1/");
  script_id(840695);
  script_tag(name:"cvss_base", value:"7.4");
 script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:S/C:C/I:C/A:C");
 script_version("$Revision: 7964 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 08:32:11 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2011-07-08 16:31:28 +0200 (Fri, 08 Jul 2011)");
  script_xref(name: "USN", value: "1165-1");
  script_cve_id("CVE-2011-2212", "CVE-2011-2512");
  script_name("Ubuntu Update for qemu-kvm USN-1165-1");

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

if(release == "UBUNTU10.10")
{

  if ((res = isdpkgvuln(pkg:"qemu-kvm", ver:"0.12.5+noroms-0ubuntu7.8", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"qemu-kvm-extras", ver:"0.12.5+noroms-0ubuntu7.8", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"qemu-kvm-extras-static", ver:"0.12.5+noroms-0ubuntu7.8", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU10.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"qemu-kvm", ver:"0.12.3+noroms-0ubuntu9.12", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"qemu-kvm-extras", ver:"0.12.3+noroms-0ubuntu9.12", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"qemu-kvm-extras-static", ver:"0.12.3+noroms-0ubuntu9.12", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU11.04")
{

  if ((res = isdpkgvuln(pkg:"qemu-kvm", ver:"0.14.0+noroms-0ubuntu4.3", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
