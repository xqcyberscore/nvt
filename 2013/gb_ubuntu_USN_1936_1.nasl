###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1936_1.nasl 7958 2017-12-01 06:47:47Z santu $
#
# Ubuntu Update for linux-lts-raring USN-1936-1
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
  script_id(841535);
  script_version("$Revision: 7958 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 07:47:47 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2013-08-27 10:00:42 +0530 (Tue, 27 Aug 2013)");
  script_cve_id("CVE-2013-1059", "CVE-2013-2148", "CVE-2013-2164", "CVE-2013-2851",
                "CVE-2013-2852", "CVE-2013-4125", "CVE-2013-4127", "CVE-2013-4247");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_name("Ubuntu Update for linux-lts-raring USN-1936-1");

  tag_insight = "Chanam Park reported a Null pointer flaw in the Linux kernel's Ceph client.
A remote attacker could exploit this flaw to cause a denial of service
(system crash). (CVE-2013-1059)

An information leak was discovered in the Linux kernel's fanotify
interface. A local user could exploit this flaw to obtain sensitive
information from kernel memory. (CVE-2013-2148)

Jonathan Salwan discovered an information leak in the Linux kernel's cdrom
driver. A local user can exploit this leak to obtain sensitive information
from kernel memory if the CD-ROM drive is malfunctioning. (CVE-2013-2164)

Kees Cook discovered a format string vulnerability in the Linux kernel's
disk block layer. A local user with administrator privileges could exploit
this flaw to gain kernel privileges. (CVE-2013-2851)

Kees Cook discovered a format string vulnerability in the Broadcom B43
wireless driver for the Linux kernel. A local user could exploit this flaw
to gain administrative privileges. (CVE-2013-2852)

Hannes Frederic Sowa discovered that the Linux kernel's IPv6 stack does not
correctly handle Router Advertisement (RA) message in some cases. A remote
attacker could exploit this flaw to cause a denial of service (system
crash). (CVE-2013-4125)

A vulnerability was discovered in the Linux kernel's vhost net driver. A
local user could cause a denial of service (system crash) by powering on a
virtual machine. (CVE-2013-4127)

Marcus Moeller and Ken Fallon discovered that the CIFS incorrectly built
certain paths. A local attacker with access to a CIFS partition could
exploit this to crash the system, leading to a denial of service.
(CVE-2013-4247)";

  tag_affected = "linux-lts-raring on Ubuntu 12.04 LTS";

  tag_solution = "Please Install the Updated Packages.";


  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name: "USN", value: "1936-1");
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-1936-1/");
  script_summary("Check for the Version of linux-lts-raring");
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

  if ((res = isdpkgvuln(pkg:"linux-image-3.8.0-29-generic", ver:"3.8.0-29.42~precise1", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
