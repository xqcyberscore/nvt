###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1383_1.nasl 7960 2017-12-01 06:58:16Z santu $
#
# Ubuntu Update for linux-ti-omap4 USN-1383-1
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_insight = "Aristide Fattori and Roberto Paleari reported a flaw in the Linux kernel's
  handling of IPv4 icmp packets. A remote user could exploit this to cause a
  denial of service. (CVE-2011-1927)

  Dan Rosenberg reported an error in the old ABI compatibility layer of ARM
  kernels. A local attacker could exploit this flaw to cause a denial of
  service or gain root privileges. (CVE-2011-1759)

  Ben Hutchings reported a flaw in the kernel's handling of corrupt LDM
  partitions. A local user could exploit this to cause a denial of service or
  escalate privileges. (CVE-2011-2182)

  The linux kernel did not properly account for PTE pages when deciding which
  task to kill in out of memory conditions. A local, unprivileged could
  exploit this flaw to cause a denial of service. (CVE-2011-2498)

  A flaw was discovered in the TOMOYO LSM's handling of mount system calls.
  An unprivileged user could oops the system causing a denial of service.
  (CVE-2011-2518)

  A flaw was discovered in the Linux kernel's AppArmor security interface
  when invalid information was written to it. An unprivileged local user
  could use this to cause a denial of service on the system. (CVE-2011-3619)";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-1383-1";
tag_affected = "linux-ti-omap4 on Ubuntu 11.04";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-1383-1/");
  script_id(840916);
  script_tag(name:"cvss_base", value:"7.2");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_version("$Revision: 7960 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 07:58:16 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2012-03-07 11:19:28 +0530 (Wed, 07 Mar 2012)");
  script_cve_id("CVE-2011-1927", "CVE-2011-1759", "CVE-2011-2182", "CVE-2011-2498",
                "CVE-2011-2518", "CVE-2011-3619");
  script_xref(name: "USN", value: "1383-1");
  script_name("Ubuntu Update for linux-ti-omap4 USN-1383-1");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
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

if(release == "UBUNTU11.04")
{

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.38-1209-omap4", ver:"2.6.38-1209.22", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
