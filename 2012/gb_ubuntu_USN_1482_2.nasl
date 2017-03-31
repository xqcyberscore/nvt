###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for clamav USN-1482-2
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_insight = "USN-1482-1 fixed vulnerabilities in ClamAV. The updated packages could fail
  to install in certain situations. This update fixes the problem.

  We apologize for the inconvenience.

  Original advisory details:

  It was discovered that ClamAV incorrectly handled certain malformed TAR
  archives. A remote attacker could create a specially-crafted TAR file
  containing malware that could escape being detected. (CVE-2012-1457,
  CVE-2012-1459)

  It was discovered that ClamAV incorrectly handled certain malformed CHM
  files. A remote attacker could create a specially-crafted CHM file
  containing malware that could escape being detected. (CVE-2012-1458)";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-1482-2";
tag_affected = "clamav on Ubuntu 12.04 LTS ,
  Ubuntu 11.10 ,
  Ubuntu 11.04";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "https://lists.ubuntu.com/archives/ubuntu-security-announce/2012-June/001730.html");
  script_id(841054);
  script_version("$Revision: 3051 $");
  script_tag(name:"last_modification", value:"$Date: 2016-04-12 11:08:04 +0200 (Tue, 12 Apr 2016) $");
  script_tag(name:"creation_date", value:"2012-06-22 10:28:29 +0530 (Fri, 22 Jun 2012)");
  script_cve_id("CVE-2012-1457", "CVE-2012-1459", "CVE-2012-1458");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_xref(name: "USN", value: "1482-2");
  script_name("Ubuntu Update for clamav USN-1482-2");

  script_summary("Check for the Version of clamav");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success", "HostDetails/OS/cpe:/o:canonical:ubuntu_linux", "ssh/login/release");
  script_tag(name : "summary" , value : tag_summary);
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

  if ((res = isdpkgvuln(pkg:"clamav", ver:"0.97.5+dfsg-1ubuntu0.12.04.2", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"clamav-daemon", ver:"0.97.5+dfsg-1ubuntu0.12.04.2", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libclamav6", ver:"0.97.5+dfsg-1ubuntu0.12.04.2", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU11.10")
{

  if ((res = isdpkgvuln(pkg:"clamav", ver:"0.97.5+dfsg-1ubuntu0.11.10.2", rls:"UBUNTU11.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"clamav-daemon", ver:"0.97.5+dfsg-1ubuntu0.11.10.2", rls:"UBUNTU11.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libclamav6", ver:"0.97.5+dfsg-1ubuntu0.11.10.2", rls:"UBUNTU11.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU11.04")
{

  if ((res = isdpkgvuln(pkg:"clamav", ver:"0.97.5+dfsg-1ubuntu0.11.04.2", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"clamav-daemon", ver:"0.97.5+dfsg-1ubuntu0.11.04.2", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libclamav6", ver:"0.97.5+dfsg-1ubuntu0.11.04.2", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
