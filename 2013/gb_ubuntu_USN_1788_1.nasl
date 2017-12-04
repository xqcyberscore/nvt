###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1788_1.nasl 7958 2017-12-01 06:47:47Z santu $
#
# Ubuntu Update for linux-lts-backport-oneiric USN-1788-1
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
tag_insight = "Emese Revfy discovered that in the Linux kernel signal handlers could leak
  address information across an exec, making it possible to bypass ASLR
  (Address Space Layout Randomization). A local user could use this flaw to
  bypass ASLR to reliably deliver an exploit payload that would otherwise be
  stopped (by ASLR). (CVE-2013-0914)

  A memory use after free error was discovered in the Linux kernel's tmpfs
  filesystem. A local user could exploit this flaw to gain privileges or
  cause a denial of service (system crash). (CVE-2013-1767)

  Mateusz Guzik discovered a race in the Linux kernel's keyring. A local user
  could exploit this flaw to cause a denial of service (system crash).
  (CVE-2013-1792)";


tag_affected = "linux-lts-backport-oneiric on Ubuntu 10.04 LTS";
tag_solution = "Please Install the Updated Packages.";

if(description)
{
  script_id(841384);
  script_version("$Revision: 7958 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 07:47:47 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2013-04-05 13:51:27 +0530 (Fri, 05 Apr 2013)");
  script_cve_id("CVE-2013-0914", "CVE-2013-1767", "CVE-2013-1792");
  script_tag(name:"cvss_base", value:"6.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:C/I:C/A:C");
  script_name("Ubuntu Update for linux-lts-backport-oneiric USN-1788-1");

  script_xref(name: "USN", value: "1788-1");
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-1788-1/");
  script_summary("Check for the Version of linux-lts-backport-oneiric");
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

  if ((res = isdpkgvuln(pkg:"linux-image-3.0.0-32-generic", ver:"3.0.0-32.51~lucid1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-3.0.0-32-generic-pae", ver:"3.0.0-32.51~lucid1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-3.0.0-32-server", ver:"3.0.0-32.51~lucid1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-3.0.0-32-virtual", ver:"3.0.0-32.51~lucid1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
