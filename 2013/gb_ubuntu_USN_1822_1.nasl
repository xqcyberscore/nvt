###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1822_1.nasl 7958 2017-12-01 06:47:47Z santu $
#
# Ubuntu Update for firefox USN-1822-1
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
tag_insight = "Multiple memory safety issues were discovered in Firefox. If the user were
  tricked into opening a specially crafted page, an attacker could possibly
  exploit these to cause a denial of service via application crash, or
  potentially execute code with the privileges of the user invoking Firefox.
  (CVE-2013-0801, CVE-2013-1669)

  Cody Crews discovered that some constructors could be used to bypass
  restrictions enforced by their Chrome Object Wrapper (COW). An attacker
  could exploit this to conduct cross-site scripting (XSS) attacks.
  (CVE-2013-1670)

  It was discovered that the file input element could expose the full local
  path under certain conditions. An attacker could potentially exploit this
  to steal sensitive information. (CVE-2013-1671)

  A use-after-free was discovered when resizing video content whilst it is
  playing. An attacker could potentially exploit this to execute code with
  the privileges of the user invoking Firefox. (CVE-2013-1674)

  It was discovered that some DOMSVGZoomEvent functions could be used
  without being properly initialized, which could lead to information
  leakage. (CVE-2013-1675)

  Abhishek Arya discovered multiple memory safety issues in Firefox. If
  the user were tricked into opening a specially crafted page, an attacker
  could possibly exploit these to cause a denial of service via application
  crash, or potentially execute code with the privileges of the user
  invoking Firefox. (CVE-2013-1676, CVE-2013-1677, CVE-2013-1678,
  CVE-2013-1679, CVE-2013-1680, CVE-2013-1681)";


tag_affected = "firefox on Ubuntu 13.04 ,
  Ubuntu 12.10 ,
  Ubuntu 12.04 LTS";
tag_solution = "Please Install the Updated Packages.";

if(description)
{
  script_id(841427);
  script_version("$Revision: 7958 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 07:47:47 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2013-05-17 09:54:38 +0530 (Fri, 17 May 2013)");
  script_cve_id("CVE-2013-0801", "CVE-2013-1669", "CVE-2013-1670", "CVE-2013-1671",
                "CVE-2013-1674", "CVE-2013-1675", "CVE-2013-1676", "CVE-2013-1677",
                "CVE-2013-1678", "CVE-2013-1679", "CVE-2013-1680", "CVE-2013-1681");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Ubuntu Update for firefox USN-1822-1");

  script_xref(name: "USN", value: "1822-1");
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-1822-1/");
  script_summary("Check for the Version of firefox");
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

  if ((res = isdpkgvuln(pkg:"firefox", ver:"21.0+build2-0ubuntu0.12.04.3", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU12.10")
{
  ## Changed version from 21.0+build2-0ubuntu0.12.10.2 to 21.0+build2-0ubuntu0.12.10
  if ((res = isdpkgvuln(pkg:"firefox", ver:"21.0+build2-0ubuntu0.12.10", rls:"UBUNTU12.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU13.04")
{
  ## Changed version from 21.0+build2-0ubuntu0.13.04.2 to 21.0+build2-0ubuntu0.13.04
  if ((res = isdpkgvuln(pkg:"firefox", ver:"21.0+build2-0ubuntu0.13.04", rls:"UBUNTU13.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
