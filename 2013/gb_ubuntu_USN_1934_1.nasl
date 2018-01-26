###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1934_1.nasl 8526 2018-01-25 06:57:37Z teissa $
#
# Ubuntu Update for linux-ti-omap4 USN-1934-1
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
  script_id(841537);
  script_version("$Revision: 8526 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-25 07:57:37 +0100 (Thu, 25 Jan 2018) $");
  script_tag(name:"creation_date", value:"2013-08-27 10:02:04 +0530 (Tue, 27 Aug 2013)");
  script_cve_id("CVE-2013-1059", "CVE-2013-2148", "CVE-2013-2851");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_name("Ubuntu Update for linux-ti-omap4 USN-1934-1");

  tag_insight = "Chanam Park reported a Null pointer flaw in the Linux kernel's Ceph client.
A remote attacker could exploit this flaw to cause a denial of service
(system crash). (CVE-2013-1059)

An information leak was discovered in the Linux kernel's fanotify
interface. A local user could exploit this flaw to obtain sensitive
information from kernel memory. (CVE-2013-2148)

Kees Cook discovered a format string vulnerability in the Linux kernel's
disk block layer. A local user with administrator privileges could exploit
this flaw to gain kernel privileges. (CVE-2013-2851)";

  tag_affected = "linux-ti-omap4 on Ubuntu 13.04";

  tag_solution = "Please Install the Updated Packages.";


  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name: "USN", value: "1934-1");
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-1934-1/");
  script_tag(name: "summary" , value: "Check for the Version of linux-ti-omap4");
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

if(release == "UBUNTU13.04")
{

  if ((res = isdpkgvuln(pkg:"linux-image-3.5.0-231-omap4", ver:"3.5.0-231.47", rls:"UBUNTU13.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
