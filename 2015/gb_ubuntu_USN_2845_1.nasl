###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for sosreport USN-2845-1
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
  script_oid("1.3.6.1.4.1.25623.1.0.842570");
  script_version("$Revision: 2741 $");
  script_tag(name:"last_modification", value:"$Date: 2016-02-26 14:45:36 +0100 (Fri, 26 Feb 2016) $");
  script_tag(name:"creation_date", value:"2015-12-18 05:44:37 +0100 (Fri, 18 Dec 2015)");
  script_cve_id("CVE-2014-3925", "CVE-2015-7529");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("Ubuntu Update for sosreport USN-2845-1");
  script_tag(name: "summary", value: "Check the version of sosreport");
  script_tag(name: "vuldetect", value: "Get the installed version with the help
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "Dolev Farhi discovered an information
disclosure issue in SoS. If the /etc/fstab file contained passwords, the
passwords were included in the SoS report. This issue only affected Ubuntu 14.04
LTS. (CVE-2014-3925)

Mateusz Guzik discovered that SoS incorrectly handled temporary files. A
local attacker could possibly use this issue to overwrite arbitrary files
or gain access to temporary file contents containing sensitive system
information. (CVE-2015-7529)");
  script_tag(name: "affected", value: "sosreport on Ubuntu 15.10 ,
  Ubuntu 15.04 ,
  Ubuntu 14.04 LTS");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");
  script_xref(name: "USN", value: "2845-1");
  script_xref(name: "URL" , value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2015-December/003234.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_summary("Check for the Version of sosreport");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
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

if(release == "UBUNTU15.04")
{

  if ((res = isdpkgvuln(pkg:"sosreport", ver:"3.2-2ubuntu0.1", rls:"UBUNTU15.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU14.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"sosreport", ver:"3.1-1ubuntu2.2", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU15.10")
{

  if ((res = isdpkgvuln(pkg:"sosreport", ver:"3.2-2ubuntu1.1", rls:"UBUNTU15.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
