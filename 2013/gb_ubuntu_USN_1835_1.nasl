###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1835_1.nasl 8466 2018-01-19 06:58:30Z teissa $
#
# Ubuntu Update for linux USN-1835-1
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
tag_insight = "A buffer overflow vulnerability was discovered in the Broadcom tg3 ethernet
  driver for the Linux kernel. A local user could exploit this flaw to cause
  a denial of service (crash the system) or potentially escalate privileges
  on the system. (CVE-2013-1929)

  A flaw was discovered in the Linux kernel's ftrace subsystem interface. A
  local user could exploit this flaw to cause a denial of service (system
  crash). (CVE-2013-3301)";


tag_affected = "linux on Ubuntu 12.10";
tag_solution = "Please Install the Updated Packages.";

if(description)
{
  script_id(841434);
  script_version("$Revision: 8466 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-19 07:58:30 +0100 (Fri, 19 Jan 2018) $");
  script_tag(name:"creation_date", value:"2013-05-27 11:54:38 +0530 (Mon, 27 May 2013)");
  script_cve_id("CVE-2013-1929", "CVE-2013-3301");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Ubuntu Update for linux USN-1835-1");

  script_xref(name: "USN", value: "1835-1");
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-1835-1/");
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

if(release == "UBUNTU12.10")
{

  if ((res = isdpkgvuln(pkg:"linux-image-3.5.0-31-generic", ver:"3.5.0-31.52", rls:"UBUNTU12.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-3.5.0-31-highbank", ver:"3.5.0-31.52", rls:"UBUNTU12.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-3.5.0-31-omap", ver:"3.5.0-31.52", rls:"UBUNTU12.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-3.5.0-31-powerpc-smp", ver:"3.5.0-31.52", rls:"UBUNTU12.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-3.5.0-31-powerpc64-smp", ver:"3.5.0-31.52", rls:"UBUNTU12.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
