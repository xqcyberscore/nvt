###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_2205_1.nasl 7957 2017-12-01 06:40:08Z santu $
#
# Ubuntu Update for tiff USN-2205-1
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
  script_id(841820);
  script_version("$Revision: 7957 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 07:40:08 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2014-05-12 09:13:38 +0530 (Mon, 12 May 2014)");
  script_cve_id("CVE-2013-4231", "CVE-2013-4232", "CVE-2013-4243", "CVE-2013-4244");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("Ubuntu Update for tiff USN-2205-1");

  tag_insight = "Pedro Ribeiro discovered that LibTIFF incorrectly handled
certain malformed images when using the gif2tiff tool. If a user or automated
system were tricked into opening a specially crafted GIF image, a remote
attacker could crash the application, leading to a denial of service, or
possibly execute arbitrary code with user privileges. This issue only
affected Ubuntu 10.04 LTS, Ubunu 12.04 LTS, Ubuntu 12.10 and Ubuntu 13.10.
(CVE-2013-4231)

Pedro Ribeiro discovered that LibTIFF incorrectly handled certain
malformed images when using the tiff2pdf tool. If a user or automated
system were tricked into opening a specially crafted TIFF image, a remote
attacker could crash the application, leading to a denial of service, or
possibly execute arbitrary code with user privileges. This issue only
affected Ubuntu 10.04 LTS, Ubunu 12.04 LTS, Ubuntu 12.10 and Ubuntu 13.10.
(CVE-2013-4232)

Murray McAllister discovered that LibTIFF incorrectly handled certain
malformed images when using the gif2tiff tool. If a user or automated
system were tricked into opening a specially crafted GIF image, a remote
attacker could crash the application, leading to a denial of service, or
possibly execute arbitrary code with user privileges. (CVE-2013-4243)

Huzaifa Sidhpurwala discovered that LibTIFF incorrectly handled certain
malformed images when using the gif2tiff tool. If a user or automated
system were tricked into opening a specially crafted GIF image, a remote
attacker could crash the application, leading to a denial of service, or
possibly execute arbitrary code with user privileges. This issue only
affected Ubuntu 10.04 LTS, Ubunu 12.04 LTS, Ubuntu 12.10 and Ubuntu 13.10.
(CVE-2013-4244)";

  tag_affected = "tiff on Ubuntu 14.04 LTS ,
  Ubuntu 13.10 ,
  Ubuntu 12.10 ,
  Ubuntu 12.04 LTS ,
  Ubuntu 10.04 LTS";

  tag_solution = "Please Install the Updated Packages.";


  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name: "USN", value: "2205-1");
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-2205-1/");
  script_summary("Check for the Version of tiff");
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

if(release == "UBUNTU14.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libtiff5:i386", ver:"4.0.3-7ubuntu0.1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU12.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libtiff4", ver:"3.9.5-2ubuntu1.6", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU10.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libtiff4", ver:"3.9.2-2ubuntu0.14", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU13.10")
{

  if ((res = isdpkgvuln(pkg:"libtiff5:i386", ver:"4.0.2-4ubuntu3.1", rls:"UBUNTU13.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU12.10")
{

  if ((res = isdpkgvuln(pkg:"libtiff5", ver:"4.0.2-1ubuntu2.3", rls:"UBUNTU12.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
