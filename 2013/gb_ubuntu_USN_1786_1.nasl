###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1786_1.nasl 7958 2017-12-01 06:47:47Z santu $
#
# Ubuntu Update for firefox USN-1786-1
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
tag_insight = "Olli Pettay, Jesse Ruderman, Boris Zbarsky, Christian Holler, Milan
  Sreckovic, Joe Drew, Andrew McCreight, Randell Jesup, Gary Kwong and
  Mats Palmgren discovered multiple memory safety issues affecting Firefox.
  If the user were tricked into opening a specially crafted page, an
  attacker could possibly exploit these to cause a denial of service via
  application crash, or potentially execute code with the privileges of the
  user invoking Firefox. (CVE-2013-0788, CVE-2013-0789)

  Ambroz Bizjak discovered an out-of-bounds array read in the
  CERT_DecodeCertPackage function of the Network Security Services (NSS)
  library when decoding certain certificates. An attacker could potentially
  exploit this to cause a denial of service via application crash.
  (CVE-2013-0791)

  Tobias Schula discovered an information leak in Firefox when the
  gfx.color_management.enablev4 preference is enabled. If the user were
  tricked into opening a specially crafted image, an attacker could
  potentially exploit this to steal confidential data. By default, the
  gfx.color_management.enablev4 preference is not enabled in Ubuntu.
  (CVE-2013-0792)

  Mariusz Mlynski discovered that timed history navigations could be used to
  load arbitrary websites with the wrong URL displayed in the addressbar. An
  attacker could exploit this to conduct cross-site scripting (XSS) or
  phishing attacks. (CVE-2013-0793)

  It was discovered that the origin indication on tab-modal dialog boxes
  could be removed, which could allow an attacker's dialog to be displayed
  over another sites content. An attacker could exploit this to conduct
  phishing attacks. (CVE-2013-0794)

  Cody Crews discovered that the cloneNode method could be used to
  bypass System Only Wrappers (SOW) to clone a protected node and bypass
  same-origin policy checks. An attacker could potentially exploit this to
  steal confidential data or execute code with the privileges of the user
  invoking Firefox. (CVE-2013-0795)

  A crash in WebGL rendering was discovered in Firefox. An attacker could
  potentially exploit this to execute code with the privileges of the user
  invoking Firefox. This issue only affects users with Intel graphics
  drivers. (CVE-2013-0796)

  Abhishek Arya discovered an out-of-bounds write in the Cairo graphics
  library. An attacker could potentially exploit this to execute code with
  the privileges of the user invoking Firefox. (CVE-2013-0800)";


tag_affected = "firefox on Ubuntu 12.10 ,
  Ubuntu 12.04 LTS ,
  Ubuntu 11.10 ,
  Ubuntu 10.04 LTS";
tag_solution = "Please Install the Updated Packages.";

if(description)
{
  script_id(841388);
  script_version("$Revision: 7958 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 07:47:47 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2013-04-05 13:52:55 +0530 (Fri, 05 Apr 2013)");
  script_cve_id("CVE-2013-0788", "CVE-2013-0789", "CVE-2013-0791", "CVE-2013-0792",
                "CVE-2013-0793", "CVE-2013-0794", "CVE-2013-0795", "CVE-2013-0796",
                "CVE-2013-0800");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Ubuntu Update for firefox USN-1786-1");

  script_xref(name: "USN", value: "1786-1");
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-1786-1/");
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

  if ((res = isdpkgvuln(pkg:"firefox", ver:"20.0+build1-0ubuntu0.12.04.3", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU11.10")
{

  if ((res = isdpkgvuln(pkg:"firefox", ver:"20.0+build1-0ubuntu0.11.10.3", rls:"UBUNTU11.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU10.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"firefox", ver:"20.0+build1-0ubuntu0.10.04.3", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU12.10")
{

  if ((res = isdpkgvuln(pkg:"firefox", ver:"20.0+build1-0ubuntu0.12.10.3", rls:"UBUNTU12.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
