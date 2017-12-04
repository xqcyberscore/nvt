###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1943_1.nasl 7958 2017-12-01 06:47:47Z santu $
#
# Ubuntu Update for linux-lts-raring USN-1943-1
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
  script_id(841549);
  script_version("$Revision: 7958 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 07:47:47 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2013-09-12 11:47:44 +0530 (Thu, 12 Sep 2013)");
  script_cve_id("CVE-2013-1060", "CVE-2013-2140", "CVE-2013-2232", "CVE-2013-2234",
                "CVE-2013-4162", "CVE-2013-4163");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Ubuntu Update for linux-lts-raring USN-1943-1");

  tag_insight = "Vasily Kulikov discovered a flaw in the Linux Kernel's perf tool that
allows for privilege escalation. A local user could exploit this flaw to
run commands as root when using the perf tool. (CVE-2013-1060)

A flaw was discovered in the Xen subsystem of the Linux kernel when it
provides read-only access to a disk that supports TRIM or SCSI UNMAP to a
guest OS. A privileged user in the guest OS could exploit this flaw to
destroy data on the disk, even though the guest OS should not be able to
write to the disk. (CVE-2013-2140)

A flaw was discovered in the Linux kernel when an IPv6 socket is used to
connect to an IPv4 destination. An unprivileged local user could exploit
this flaw to cause a denial of service (system crash). (CVE-2013-2232)

An information leak was discovered in the IPSec key_socket implementation
in the Linux kernel. An local user could exploit this flaw to examine
potentially sensitive information in kernel memory. (CVE-2013-2234)

Hannes Frederic Sowa discovered a flaw in setsockopt UDP_CORK option in the
Linux kernel's IPv6 stack. A local user could exploit this flaw to cause a
denial of service (system crash). (CVE-2013-4162)

Hannes Frederic Sowa discovered a flaw in the IPv6 subsystem of the Linux
kernel when the IPV6_MTU setsockopt option has been specified in
combination with the UDP_CORK option. A local user could exploit this flaw
to cause a denial of service (system crash). (CVE-2013-4163)";

  tag_affected = "linux-lts-raring on Ubuntu 12.04 LTS";

  tag_solution = "Please Install the Updated Packages.";


  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name: "USN", value: "1943-1");
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-1943-1/");
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

  if ((res = isdpkgvuln(pkg:"linux-image-3.8.0-30-generic", ver:"3.8.0-30.44~precise1", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
