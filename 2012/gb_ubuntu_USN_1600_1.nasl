###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1600_1.nasl 7960 2017-12-01 06:58:16Z santu $
#
# Ubuntu Update for firefox USN-1600-1
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
tag_insight = "Henrik Skupin, Jesse Ruderman, Christian Holler, Soroush Dalili and others
  discovered several memory corruption flaws in Firefox. If a user were
  tricked into opening a specially crafted web page, a remote attacker could
  cause Firefox to crash or potentially execute arbitrary code as the user
  invoking the program. (CVE-2012-3982, CVE-2012-3983, CVE-2012-3988,
  CVE-2012-3989)

  David Bloom and Jordi Chancel discovered that Firefox did not always
  properly handle the &lt;select&gt; element. A remote attacker could exploit this
  to conduct URL spoofing and clickjacking attacks. (CVE-2012-3984)
  
  Collin Jackson discovered that Firefox did not properly follow the HTML5
  specification for document.domain behavior. A remote attacker could exploit
  this to conduct cross-site scripting (XSS) attacks via javascript
  execution. (CVE-2012-3985)
  
  Johnny Stenback discovered that Firefox did not properly perform security
  checks on tests methods for DOMWindowUtils. (CVE-2012-3986)
  
  Alice White discovered that the security checks for GetProperty could be
  bypassed when using JSAPI. If a user were tricked into opening a specially
  crafted web page, a remote attacker could exploit this to execute arbitrary
  code as the user invoking the program. (CVE-2012-3991)
  
  Mariusz Mlynski discovered a history state error in Firefox. A remote
  attacker could exploit this to spoof the location property to inject script
  or intercept posted data. (CVE-2012-3992)
  
  Mariusz Mlynski and others discovered several flays in Firefox that allowed
  a remote attacker to conduct cross-site scripting (XSS) attacks.
  (CVE-2012-3993, CVE-2012-3994, CVE-2012-4184)
  
  Abhishek Arya, Atte Kettunen and others discovered several memory flaws in
  Firefox when using the Address Sanitizer tool. If a user were tricked into
  opening a specially crafted web page, a remote attacker could cause Firefox
  to crash or potentially execute arbitrary code as the user invoking the
  program. (CVE-2012-3990, CVE-2012-3995, CVE-2012-4179, CVE-2012-4180,
  CVE-2012-4181, CVE-2012-4182, CVE-2012-4183, CVE-2012-4185, CVE-2012-4186,
  CVE-2012-4187, CVE-2012-4188)";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-1600-1";
tag_affected = "firefox on Ubuntu 12.04 LTS ,
  Ubuntu 11.10 ,
  Ubuntu 11.04 ,
  Ubuntu 10.04 LTS";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-1600-1/");
  script_id(841181);
  script_version("$Revision: 7960 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 07:58:16 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2012-10-11 10:04:22 +0530 (Thu, 11 Oct 2012)");
  script_cve_id("CVE-2012-3982", "CVE-2012-3983", "CVE-2012-3988", "CVE-2012-3989",
                "CVE-2012-3984", "CVE-2012-3985", "CVE-2012-3986", "CVE-2012-3991",
                "CVE-2012-3992", "CVE-2012-3993", "CVE-2012-3994", "CVE-2012-4184",
                "CVE-2012-3990", "CVE-2012-3995", "CVE-2012-4179", "CVE-2012-4180",
                "CVE-2012-4181", "CVE-2012-4182", "CVE-2012-4183", "CVE-2012-4185",
                "CVE-2012-4186", "CVE-2012-4187", "CVE-2012-4188");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name: "USN", value: "1600-1");
  script_name("Ubuntu Update for firefox USN-1600-1");

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

if(release == "UBUNTU10.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"firefox", ver:"16.0+build1-0ubuntu0.10.04.1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU12.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"firefox", ver:"16.0+build1-0ubuntu0.12.04.1", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU11.10")
{

  if ((res = isdpkgvuln(pkg:"firefox", ver:"16.0+build1-0ubuntu0.11.10.1", rls:"UBUNTU11.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU11.04")
{

  if ((res = isdpkgvuln(pkg:"firefox", ver:"16.0+build1-0ubuntu0.11.04.1", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
