###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for eglibc USN-1991-1
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
  script_id(841605);
  script_version("$Revision: 2932 $");
  script_tag(name:"last_modification", value:"$Date: 2016-03-24 09:15:28 +0100 (Thu, 24 Mar 2016) $");
  script_tag(name:"creation_date", value:"2013-10-29 16:50:28 +0530 (Tue, 29 Oct 2013)");
  script_cve_id("CVE-2012-4412", "CVE-2012-4424", "CVE-2013-0242", "CVE-2013-1914", "CVE-2013-4237", "CVE-2013-4332");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Ubuntu Update for eglibc USN-1991-1");

  tag_insight = "It was discovered that the GNU C Library incorrectly handled the strcoll()
function. An attacker could use this issue to cause a denial of service, or
possibly execute arbitrary code. (CVE-2012-4412, CVE-2012-4424)

It was discovered that the GNU C Library incorrectly handled multibyte
characters in the regular expression matcher. An attacker could use this
issue to cause a denial of service. (CVE-2013-0242)

It was discovered that the GNU C Library incorrectly handled large numbers
of domain conversion results in the getaddrinfo() function. An attacker
could use this issue to cause a denial of service. (CVE-2013-1914)

It was discovered that the GNU C Library readdir_r() function incorrectly
handled crafted NTFS or CIFS images. An attacker could use this issue to
cause a denial of service, or possibly execute arbitrary code.
(CVE-2013-4237)

It was discovered that the GNU C Library incorrectly handled memory
allocation. An attacker could use this issue to cause a denial of service.
(CVE-2013-4332)";

  tag_affected = "eglibc on Ubuntu 13.04 ,
  Ubuntu 12.10 ,
  Ubuntu 12.04 LTS ,
  Ubuntu 10.04 LTS";

  tag_solution = "Please Install the Updated Packages.";


  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name: "USN", value: "1991-1");
  script_xref(name: "URL" , value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2013-October/002279.html");
  script_summary("Check for the Version of eglibc");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success", "HostDetails/OS/cpe:/o:canonical:ubuntu_linux", "ssh/login/release");
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

  if ((res = isdpkgvuln(pkg:"libc6", ver:"2.15-0ubuntu10.5", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU10.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libc6", ver:"2.11.1-0ubuntu7.13", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU12.10")
{

  if ((res = isdpkgvuln(pkg:"libc6", ver:"2.15-0ubuntu20.2", rls:"UBUNTU12.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU13.04")
{

  if ((res = isdpkgvuln(pkg:"libc6", ver:"2.17-0ubuntu5.1", rls:"UBUNTU13.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
