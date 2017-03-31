###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for linux-ec2 USN-1453-1
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
tag_insight = "A flaw was found in the Linux's kernels ext4 file system when mounted with
  a journal. A local, unprivileged user could exploit this flaw to cause a
  denial of service. (CVE-2011-4086)

  A flaw was found in the Linux kernel's KVM (Kernel Virtual Machine) virtual
  cpu setup. An unprivileged local user could exploit this flaw to crash the
  system leading to a denial of service. (CVE-2012-1601)

  Steve Grubb reported a flaw with Linux fscaps (file system base
  capabilities) when used to increase the permissions of a process. For
  application on which fscaps are in use a local attacker can disable address
  space randomization to make attacking the process with raised privileges
  easier. (CVE-2012-2123)";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-1453-1";
tag_affected = "linux-ec2 on Ubuntu 10.04 LTS";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "https://lists.ubuntu.com/archives/ubuntu-security-announce/2012-May/001694.html");
  script_id(841017);
  script_version("$Revision: 3051 $");
  script_tag(name:"last_modification", value:"$Date: 2016-04-12 11:08:04 +0200 (Tue, 12 Apr 2016) $");
  script_tag(name:"creation_date", value:"2012-05-28 11:00:11 +0530 (Mon, 28 May 2012)");
  script_cve_id("CVE-2011-4086", "CVE-2012-1601", "CVE-2012-2123");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name: "USN", value: "1453-1");
  script_name("Ubuntu Update for linux-ec2 USN-1453-1");

  script_summary("Check for the Version of linux-ec2");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success", "HostDetails/OS/cpe:/o:canonical:ubuntu_linux", "ssh/login/release");
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

if(release == "UBUNTU10.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.32-345-ec2", ver:"2.6.32-345.48", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
