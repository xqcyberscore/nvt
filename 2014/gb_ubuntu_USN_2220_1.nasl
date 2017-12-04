###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_2220_1.nasl 7957 2017-12-01 06:40:08Z santu $
#
# Ubuntu Update for linux-ec2 USN-2220-1
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.841837");
  script_version("$Revision: 7957 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 07:40:08 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2014-06-02 16:10:59 +0530 (Mon, 02 Jun 2014)");
  script_cve_id("CVE-2014-1738", "CVE-2014-1737", "CVE-2013-7339", "CVE-2014-2678");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Ubuntu Update for linux-ec2 USN-2220-1");

  tag_insight = "Matthew Daley reported an information leak in the floppy disk
driver of the Linux kernel. An unprivileged local user could exploit this flaw
to obtain potentially sensitive information from kernel memory. (CVE-2014-1738)

Matthew Daley reported a flaw in the handling of ioctl commands by the
floppy disk driver in the Linux kernel. An unprivileged local user could
exploit this flaw to gain administrative privileges if the floppy disk
module is loaded. (CVE-2014-1737)

A flaw was discovered in the Reliable Datagram Sockets (RDS) protocol
implementation in the Linux kernel for systems that lack RDS transports. An
unprivileged local user could exploit this flaw to cause a denial of
service (system crash). (CVE-2013-7339)

An error was discovered in the Reliable Datagram Sockets (RDS) protocol
stack in the Linux kernel. A local user could exploit this flaw to cause a
denial of service (system crash) or possibly have unspecified other impact.
(CVE-2014-2678)";

  tag_affected = "linux-ec2 on Ubuntu 10.04 LTS";

  tag_solution = "Please Install the Updated Packages.";


  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name: "USN", value: "2220-1");
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-2220-1/");
  script_summary("Check for the Version of linux-ec2");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
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

if(release == "UBUNTU10.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.32-364-ec2", ver:"2.6.32-364.77", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
