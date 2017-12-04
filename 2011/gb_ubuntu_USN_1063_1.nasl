###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1063_1.nasl 7964 2017-12-01 07:32:11Z santu $
#
# Ubuntu Update for qemu-kvm vulnerability USN-1063-1
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
tag_insight = "Neil Wilson discovered that if VNC passwords were blank in QEMU
  configurations, access to VNC sessions was allowed without a password
  instead of being disabled. A remote attacker could connect to running
  VNC sessions of QEMU and directly control the system. By default, QEMU
  does not start VNC sessions.";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-1063-1";
tag_affected = "qemu-kvm vulnerability on Ubuntu 9.10 ,
  Ubuntu 10.04 LTS ,
  Ubuntu 10.10";
tag_solution = "Please Install the Updated Packages.";


if(description)
{
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-1063-1/");
  script_id(840585);
  script_version("$Revision: 7964 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 08:32:11 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2011-02-16 14:19:17 +0100 (Wed, 16 Feb 2011)");
  script_xref(name: "USN", value: "1063-1");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:H/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2011-0011");
  script_name("Ubuntu Update for qemu-kvm vulnerability USN-1063-1");

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

if(release == "UBUNTU9.10")
{

  if ((res = isdpkgvuln(pkg:"kvm", ver:"84+dfsg-0ubuntu16+0.11.0+0ubuntu6.4", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"qemu-kvm", ver:"0.11.0-0ubuntu6.4", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"qemu-arm-static", ver:"0.11.0-0ubuntu6.4", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"qemu-kvm-extras", ver:"0.11.0-0ubuntu6.4", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"qemu", ver:"0.11.0-0ubuntu6.4", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU10.10")
{

  if ((res = isdpkgvuln(pkg:"kvm", ver:"84+dfsg-0ubuntu16+0.12.5+noroms+0ubuntu7.2", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"qemu-kvm", ver:"0.12.5+noroms-0ubuntu7.2", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"qemu-arm-static", ver:"0.12.5+noroms-0ubuntu7.2", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"qemu-kvm-extras-static", ver:"0.12.5+noroms-0ubuntu7.2", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"qemu-kvm-extras", ver:"0.12.5+noroms-0ubuntu7.2", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"qemu", ver:"0.12.5+noroms-0ubuntu7.2", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"qemu-common", ver:"0.12.5+noroms-0ubuntu7.2", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU10.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"kvm", ver:"84+dfsg-0ubuntu16+0.12.3+noroms+0ubuntu9.4", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"qemu-kvm", ver:"0.12.3+noroms-0ubuntu9.4", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"qemu-arm-static", ver:"0.12.3+noroms-0ubuntu9.4", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"qemu-kvm-extras-static", ver:"0.12.3+noroms-0ubuntu9.4", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"qemu-kvm-extras", ver:"0.12.3+noroms-0ubuntu9.4", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"qemu", ver:"0.12.3+noroms-0ubuntu9.4", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"qemu-common", ver:"0.12.3+noroms-0ubuntu9.4", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
