###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for linux-aws USN-3220-3
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843083");
  script_version("$Revision: 5535 $");
  script_tag(name:"last_modification", value:"$Date: 2017-03-10 12:50:09 +0100 (Fri, 10 Mar 2017) $");
  script_tag(name:"creation_date", value:"2017-03-09 05:01:39 +0100 (Thu, 09 Mar 2017)");
  script_cve_id("CVE-2017-2636");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("Ubuntu Update for linux-aws USN-3220-3");
  script_tag(name: "summary", value: "Check the version of linux-aws");
  script_tag(name: "vuldetect", value: "Get the installed version with the help of 
  detect NVT and check if the version is vulnerable or not."); 
  script_tag(name: "insight", value: "USN-3220-1 fixed a vulnerability in the 
  Linux kernel. This update provides the corresponding updates for the Linux 
  kernel for Amazon Web Services (AWS). Alexander Popov discovered that the N_HDLC 
  line discipline implementation in the Linux kernel contained a double-free 
  vulnerability. A local attacker could use this to cause a denial of service 
  (system crash) or possibly gain administrative privileges."); 
  script_tag(name: "affected", value: "linux-aws on Ubuntu 16.04 LTS");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "USN", value: "3220-3");
  script_xref(name: "URL" , value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2017-March/003766.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success", "HostDetails/OS/cpe:/o:canonical:ubuntu_linux", "ssh/login/release");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = get_kb_item("ssh/login/release");

res = "";
if(release == NULL){
  exit(0);
}

if(release == "UBUNTU16.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"linux-image-4.4.0-1007-aws", ver:"4.4.0-1007.16", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-aws", ver:"4.4.0.1007.8", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}