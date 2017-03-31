###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for openoffice.org USN-1537-1
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
tag_insight = "It was discovered that OpenOffice.org incorrectly handled certain
  encryption tags in Open Document Text (.odt) files. If a user were tricked
  into opening a specially crafted file, an attacker could cause
  OpenOffice.org to crash or possibly execute arbitrary code with the
  privileges of the user invoking the program.";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-1537-1";
tag_affected = "openoffice.org on Ubuntu 10.04 LTS";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "https://lists.ubuntu.com/archives/ubuntu-security-announce/2012-August/001790.html");
  script_id(841106);
  script_version("$Revision: 3052 $");
  script_tag(name:"last_modification", value:"$Date: 2016-04-12 11:30:30 +0200 (Tue, 12 Apr 2016) $");
  script_tag(name:"creation_date", value:"2012-08-14 10:40:36 +0530 (Tue, 14 Aug 2012)");
  script_cve_id("CVE-2012-2665");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_xref(name: "USN", value: "1537-1");
  script_name("Ubuntu Update for openoffice.org USN-1537-1");

  script_summary("Check for the Version of openoffice.org");
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

if(release == "UBUNTU10.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"openoffice.org-core", ver:"1:3.2.0-7ubuntu4.4", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
