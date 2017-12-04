###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1969_1.nasl 7958 2017-12-01 06:47:47Z santu $
#
# Ubuntu Update for linux-ti-omap4 USN-1969-1
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
  script_id(841570);
  script_version("$Revision: 7958 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 07:47:47 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2013-10-03 10:20:13 +0530 (Thu, 03 Oct 2013)");
  script_cve_id("CVE-2013-4254", "CVE-2013-1819");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Ubuntu Update for linux-ti-omap4 USN-1969-1");

  tag_insight = "Vince Weaver discovered a flaw in the perf subsystem of the Linux kernel on
ARM platforms. A local user could exploit this flaw to gain privileges or
cause a denial of service (system crash). (CVE-2013-4254)

A failure to validate block numbers was discovered in the Linux kernel's
implementation of the XFS filesystem. A local user can cause a denial of
service (system crash) if they can mount, or cause to be mounted a
corrupted or special crafted XFS filesystem. (CVE-2013-1819)";

  tag_affected = "linux-ti-omap4 on Ubuntu 12.04 LTS";

  tag_solution = "Please Install the Updated Packages.";


  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name: "USN", value: "1969-1");
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-1969-1/");
  script_summary("Check for the Version of linux-ti-omap4");
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

  if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-1438-omap4", ver:"3.2.0-1438.57", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}