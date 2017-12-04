###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for cpio USN-2456-1
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
  script_oid("1.3.6.1.4.1.25623.1.0.842040");
  script_version("$Revision: 7956 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 06:53:44 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2015-01-23 12:57:52 +0100 (Fri, 23 Jan 2015)");
  script_cve_id("CVE-2014-9112", "CVE-2010-0624");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("Ubuntu Update for cpio USN-2456-1");
  script_tag(name: "summary", value: "Check the version of cpio");
  script_tag(name: "vuldetect", value: "Get the installed version with the help of
detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "Michal Zalewski discovered an out of bounds
write issue in the process_copy_in function of GNU cpio. An attacker could specially
craft a cpio archive that could create a denial of service or possibly
execute arbitrary code. (CVE-2014-9112)

Jakob Lell discovered a heap-based buffer overflow in the rmt_read__
function of GNU cpio's rmt client functionality. An attacker
controlling a remote rmt server could use this to cause a denial of
service or possibly execute arbitrary code. This issue only affected
Ubuntu 10.04 LTS. (CVE-2010-0624)");
  script_tag(name: "affected", value: "cpio on Ubuntu 14.10 ,
  Ubuntu 14.04 LTS ,
  Ubuntu 12.04 LTS ,
  Ubuntu 10.04 LTS");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");
  script_xref(name: "USN", value: "2456-1");
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-2456-1/");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
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

if(release == "UBUNTU14.10")
{

  if ((res = isdpkgvuln(pkg:"cpio", ver:"2.11+dfsg-2ubuntu1.1", rls:"UBUNTU14.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU14.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"cpio", ver:"2.11+dfsg-1ubuntu1.1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU12.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"cpio", ver:"2.11-7ubuntu3.1", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU10.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"cpio", ver:"2.10-1ubuntu2.1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
