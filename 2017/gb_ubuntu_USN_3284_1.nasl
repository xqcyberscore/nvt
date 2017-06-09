###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for openvpn USN-3284-1
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
  script_oid("1.3.6.1.4.1.25623.1.0.843159");
  script_version("$Revision: 6167 $");
  script_tag(name:"last_modification", value:"$Date: 2017-05-19 08:16:05 +0200 (Fri, 19 May 2017) $");
  script_tag(name:"creation_date", value:"2017-05-12 06:50:37 +0200 (Fri, 12 May 2017)");
  script_cve_id("CVE-2017-7478", "CVE-2017-7479");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("Ubuntu Update for openvpn USN-3284-1");
  script_tag(name: "summary", value: "Check the version of openvpn");
  script_tag(name: "vuldetect", value: "Get the installed version with the help of 
  detect NVT and check if the version is vulnerable or not."); 
  script_tag(name: "insight", value: "It was discovered that OpenVPN improperly 
  triggered an assert when receiving an oversized control packet in some 
  situations. A remote attacker could use this to cause a denial of service 
  (server or client crash). (CVE-2017-7478) It was discovered that OpenVPN 
  improperly triggered an assert when packet ids rolled over. An authenticated 
  remote attacker could use this to cause a denial of service (application crash). 
  (CVE-2017-7479)"); 
  script_tag(name: "affected", value: "openvpn on Ubuntu 17.04");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "USN", value: "3284-1");
  script_xref(name: "URL" , value: "https://www.ubuntu.com/usn/usn-3284-1");
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

if(release == "UBUNTU17.04")
{

  if ((res = isdpkgvuln(pkg:"openvpn", ver:"2.4.0-4ubuntu1.2", rls:"UBUNTU17.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
