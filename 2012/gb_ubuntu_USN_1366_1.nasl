###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1366_1.nasl 7960 2017-12-01 06:58:16Z santu $
#
# Ubuntu Update for devscripts USN-1366-1
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
tag_insight = "Paul Wise discovered that debdiff did not properly sanitize its input when
  processing .dsc and .changes files. If debdiff processed a crafted file, an
  attacker could execute arbitrary code with the privileges of the user invoking
  the program. (CVE-2012-0210)

  Raphael Geissert discovered that debdiff did not properly sanitize its input
  when processing source packages. If debdiff processed an original source
  tarball, with crafted filenames in the top-level directory, an attacker could
  execute arbitrary code with the privileges of the user invoking the program.
  (CVE-2012-0211)

  Raphael Geissert discovered that debdiff did not properly sanitize its input
  when processing filename parameters. If debdiff processed a crafted filename
  parameter, an attacker could execute arbitrary code with the privileges of the
  user invoking the program. (CVE-2012-0212)";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-1366-1";
tag_affected = "devscripts on Ubuntu 11.04 ,
  Ubuntu 10.10 ,
  Ubuntu 10.04 LTS ,
  Ubuntu 8.04 LTS";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-1366-1/");
  script_id(840905);
  script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_version("$Revision: 7960 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 07:58:16 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2012-02-21 19:00:44 +0530 (Tue, 21 Feb 2012)");
  script_cve_id("CVE-2012-0210", "CVE-2012-0211", "CVE-2012-0212");
  script_xref(name: "USN", value: "1366-1");
  script_name("Ubuntu Update for devscripts USN-1366-1");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages");
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

if(release == "UBUNTU10.10")
{

  if ((res = isdpkgvuln(pkg:"devscripts", ver:"2.10.67ubuntu1.1", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU10.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"devscripts", ver:"2.10.61ubuntu5.1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU11.04")
{

  if ((res = isdpkgvuln(pkg:"devscripts", ver:"2.10.69ubuntu2.1", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU8.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"devscripts", ver:"2.10.11ubuntu5.8.04.5", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
