###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for thunderbird USN-2712-1
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.842421");
  script_version("$Revision: 7956 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 06:53:44 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2015-08-26 09:23:18 +0200 (Wed, 26 Aug 2015)");
  script_cve_id("CVE-2015-4473", "CVE-2015-4487", "CVE-2015-4488", "CVE-2015-4489",
                "CVE-2015-4491");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("Ubuntu Update for thunderbird USN-2712-1");
  script_tag(name: "summary", value: "Check the version of thunderbird");
  script_tag(name: "vuldetect", value: "Get the installed version with the help
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "Gary Kwong, Christian Holler, and Byron
Campen discovered multiple memory safety issues in Thunderbird. If a user were
tricked in to opening a specially crafted message, an attacker could potentially
exploit these to cause a denial of service via application crash, or execute
arbitrary code with the privileges ofthe user invoking Thunderbird.
(CVE-2015-4473)

Ronald Crane reported 3 security issues. If a user were tricked in to
opening a specially crafted message, an attacker could potentially
exploit these, in combination with another security vulnerability, to
cause a denial of service via application crash, or execute arbitrary
code with the privileges of the user invoking Thunderbird. (CVE-2015-4487,
CVE-2015-4488, CVE-2015-4489)

Gustavo Grieco discovered a heap overflow in gdk-pixbuf. If a user were
tricked in to opening a specially crafted message, an attacker could
potentially exploit this to cause a denial of service via application
crash or execute arbitrary code with the priviliges of the user invoking
Thunderbird. (CVE-2015-4491)");
  script_tag(name: "affected", value: "thunderbird on Ubuntu 14.04 LTS ,
  Ubuntu 12.04 LTS");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");
  script_xref(name: "USN", value: "2712-1");
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-2712-1/");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = get_kb_item("ssh/login/release");

res = "";
if(release == NULL){
  exit(0);
}

if(release == "UBUNTU14.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"thunderbird", ver:"1:38.2.0+build1-0ubuntu0.14.04.1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU12.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"thunderbird", ver:"1:38.2.0+build1-0ubuntu0.12.04.2", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
