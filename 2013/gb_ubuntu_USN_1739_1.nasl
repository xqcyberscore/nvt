###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1739_1.nasl 9650 2018-04-27 08:51:00Z cfischer $
#
# Ubuntu Update for linux USN-1739-1
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
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-1739-1/");
  script_oid("1.3.6.1.4.1.25623.1.0.841330");
  script_version("$Revision: 9650 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-27 10:51:00 +0200 (Fri, 27 Apr 2018) $");
  script_tag(name:"creation_date", value:"2013-02-22 10:14:11 +0530 (Fri, 22 Feb 2013)");
  script_cve_id("CVE-2013-0871");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_xref(name: "USN", value: "1739-1");
  script_name("Ubuntu Update for linux USN-1739-1");

  script_tag(name: "summary" , value: "Check for the Version of linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU11\.10");
  script_tag(name : "affected" , value : "linux on Ubuntu 11.10");
  script_tag(name : "insight" , value : "Suleiman Souhlal, Salman Qazi, Aaron Durbin and Michael Davidson discovered
  a race condition in the Linux kernel's ptrace syscall. An unprivileged
  local attacker could exploit this flaw to run programs as an administrator.");
  script_tag(name : "solution" , value : "Please Install the Updated Packages.");
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

if(release == "UBUNTU11.10")
{

  if ((res = isdpkgvuln(pkg:"linux-image-3.0.0-31-generic", ver:"3.0.0-31.49", rls:"UBUNTU11.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-3.0.0-31-generic-pae", ver:"3.0.0-31.49", rls:"UBUNTU11.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-3.0.0-31-omap", ver:"3.0.0-31.49", rls:"UBUNTU11.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-3.0.0-31-powerpc", ver:"3.0.0-31.49", rls:"UBUNTU11.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-3.0.0-31-powerpc-smp", ver:"3.0.0-31.49", rls:"UBUNTU11.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-3.0.0-31-powerpc64-smp", ver:"3.0.0-31.49", rls:"UBUNTU11.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-3.0.0-31-server", ver:"3.0.0-31.49", rls:"UBUNTU11.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-3.0.0-31-virtual", ver:"3.0.0-31.49", rls:"UBUNTU11.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}