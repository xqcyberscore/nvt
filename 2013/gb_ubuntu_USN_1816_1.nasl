###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1816_1.nasl 7958 2017-12-01 06:47:47Z santu $
#
# Ubuntu Update for clamav USN-1816-1
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
tag_insight = "It was discovered that ClamAV would incorrectly parse a UPX-packed
  executable, leading to possible inappropriate heap reads. An attacker
  could use this issue to cause ClamAV to crash, resulting in a denial of
  service, or possibly execute arbitrary code. (CVE-2013-2020)

  It was discovered that ClamAV would incorrectly parse a PDF document,
  potentially writing beyond the size of a static array. An attacker could
  use this issue to cause ClamAV to crash, resulting in a denial of service,
  or possibly execute arbitrary code. (CVE-2013-2021)";


tag_affected = "clamav on Ubuntu 13.04 ,
  Ubuntu 12.10 ,
  Ubuntu 12.04 LTS ,
  Ubuntu 11.10 ,
  Ubuntu 10.04 LTS";
tag_solution = "Please Install the Updated Packages.";

if(description)
{
  script_id(841417);
  script_version("$Revision: 7958 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 07:47:47 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2013-05-06 13:53:41 +0530 (Mon, 06 May 2013)");
  script_cve_id("CVE-2013-2020", "CVE-2013-2021");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Ubuntu Update for clamav USN-1816-1");

  script_xref(name: "USN", value: "1816-1");
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-1816-1/");
  script_summary("Check for the Version of clamav");
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

if(release == "UBUNTU12.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"clamav", ver:"0.97.8+dfsg-1ubuntu1.12.04.1", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU11.10")
{

  if ((res = isdpkgvuln(pkg:"clamav", ver:"0.97.8+dfsg-1ubuntu1.11.10.1", rls:"UBUNTU11.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU10.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"clamav", ver:"0.97.8+dfsg-1ubuntu1.10.04.1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU12.10")
{

  if ((res = isdpkgvuln(pkg:"clamav", ver:"0.97.8+dfsg-1ubuntu1.12.10.1", rls:"UBUNTU12.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}

## Changed clamav version to 0.97.8+dfsg-1ubuntu1.13.04, as ubuntu version is 13.04 instead of 13.04.1
if(release == "UBUNTU13.04")
{

  if ((res = isdpkgvuln(pkg:"clamav", ver:"0.97.8+dfsg-1ubuntu1.13.04", rls:"UBUNTU13.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
