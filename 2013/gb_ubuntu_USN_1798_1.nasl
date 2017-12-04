###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1798_1.nasl 7958 2017-12-01 06:47:47Z santu $
#
# Ubuntu Update for linux-ec2 USN-1798-1
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
tag_insight = "Mathias Krause discovered several errors in the Linux kernel's xfrm_user
  implementation. A local attacker could exploit these flaws to examine parts
  of kernel memory. (CVE-2012-6537)

  Mathias Krause discovered information leak in the Linux kernel's compat
  ioctl interface. A local user could exploit the flaw to examine parts of
  kernel stack memory (CVE-2012-6539)

  Mathias Krause discovered an information leak in the Linux kernel's
  getsockopt for IP_VS_SO_GET_TIMEOUT. A local user could exploit this flaw
  to examine parts of kernel stack memory. (CVE-2012-6540)

  Emese Revfy discovered that in the Linux kernel signal handlers could leak
  address information across an exec, making it possible to by pass ASLR
  (Address Space Layout Randomization). A local user could use this flaw to
  by pass ASLR to reliably deliver an exploit payload that would otherwise be
  stopped (by ASLR). (CVE-2013-0914)

  A memory use after free error was discover in the Linux kernel's tmpfs
  filesystem. A local user could exploit this flaw to gain privileges or
  cause a denial of service (system crash). (CVE-2013-1767)

  Mateusz Guzik discovered a race in the Linux kernel's keyring. A local user
  could exploit this flaw to cause a denial of service (system crash).
  (CVE-2013-1792)";


tag_affected = "linux-ec2 on Ubuntu 10.04 LTS";
tag_solution = "Please Install the Updated Packages.";

if(description)
{
  script_id(841391);
  script_version("$Revision: 7958 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 07:47:47 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2013-04-15 10:17:29 +0530 (Mon, 15 Apr 2013)");
  script_cve_id("CVE-2012-6537", "CVE-2012-6539", "CVE-2012-6540", "CVE-2013-0914",
                "CVE-2013-1767", "CVE-2013-1792");
  script_tag(name:"cvss_base", value:"6.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:C/I:C/A:C");
  script_name("Ubuntu Update for linux-ec2 USN-1798-1");

  script_xref(name: "USN", value: "1798-1");
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-1798-1/");
  script_summary("Check for the Version of linux-ec2");
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

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.32-351-ec2", ver:"2.6.32-351.63", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
