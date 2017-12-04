###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_2052_1.nasl 7958 2017-12-01 06:47:47Z santu $
#
# Ubuntu Update for firefox USN-2052-1
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_id(841651);
  script_version("$Revision: 7958 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 07:47:47 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2013-12-17 12:05:51 +0530 (Tue, 17 Dec 2013)");
  script_cve_id("CVE-2013-5609", "CVE-2013-5610", "CVE-2013-5611", "CVE-2013-5612",
                "CVE-2013-5614", "CVE-2013-5616", "CVE-2013-5618", "CVE-2013-5619",
                "CVE-2013-6671", "CVE-2013-6672", "CVE-2013-6673", "CVE-2013-5613",
                "CVE-2013-5615", "CVE-2013-6629", "CVE-2013-6630");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Ubuntu Update for firefox USN-2052-1");

  tag_insight = "Ben Turner, Bobby Holley, Jesse Ruderman, Christian Holler
and Christoph Diehl discovered multiple memory safety issues in Firefox. If
a user were tricked in to opening a specially crafted website, an attacker
could potentially exploit these to cause a denial of service via application
crash, or execute arbitrary code with the privileges of the user invoking
Firefox. (CVE-2013-5609, CVE-2013-5610)

Myk Melez discovered that the doorhanger notification for web app
installation could persist between page navigations. An attacker could
potentially exploit this to conduct clickjacking attacks. (CVE-2013-5611)

Masato Kinugawa discovered that pages with missing character set encoding
information can inherit character encodings across navigations from
another domain. An attacker could potentially exploit this to conduct
cross-site scripting attacks. (CVE-2013-5612)

Daniel Veditz discovered that a sandboxed iframe could use an object
element to bypass its own restrictions. (CVE-2013-5614)

Tyson Smith and Jesse Schwartzentruber discovered a use-after-free in
event listeners. An attacker could potentially exploit this to cause a
denial of service via application crash, or execute arbitrary code with
the privileges of the user invoking Firefox. (CVE-2013-5616)

A use-after-free was discovered in the table editing interface. An
attacker could potentially exploit this to cause a denial of service via
application crash, or execute arbitrary code with the privileges of the
user invoking Firefox. (CVE-2013-5618)

Dan Gohman discovered that binary search algorithms in Spidermonkey
used arithmetic prone to overflow in several places. However, this
is issue not believed to be exploitable. (CVE-2013-5619)

Tyson Smith and Jesse Schwartzentruber discovered a crash when inserting
an ordered list in to a document using script. An attacker could
potentially exploit this to execute arbitrary code with the privileges
of the user invoking Firefox. (CVE-2013-6671)

Vincent Lefevre discovered that web content could access clipboard data
under certain circumstances, resulting in information disclosure.
(CVE-2013-6672)

Sijie Xia discovered that trust settings for built-in EV root certificates
were ignored under certain circumstances, removing the ability for a user
to manually untrust certificates from specific authorities.
(CVE-2013-6673)

Tyson Smith, Jesse Schwartzentruber and Atte Kettunen discovered a
use-after-free in functions for synthetic mouse movement handling. An
attacker could potentially exploit this to cause a denial of service via
application crash, ...

  Description truncated, for more information please check the Reference URL";

  tag_affected = "firefox on Ubuntu 13.10 ,
  Ubuntu 13.04 ,
  Ubuntu 12.10 ,
  Ubuntu 12.04 LTS";

  tag_solution = "Please Install the Updated Packages.";


  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name: "USN", value: "2052-1");
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-2052-1/");
  script_summary("Check for the Version of firefox");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
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

if(release == "UBUNTU12.10")
{

  if ((res = isdpkgvuln(pkg:"firefox", ver:"26.0+build2-0ubuntu0.12.10.2", rls:"UBUNTU12.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU12.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"firefox", ver:"26.0+build2-0ubuntu0.12.04.2", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU13.10")
{

  if ((res = isdpkgvuln(pkg:"firefox", ver:"26.0+build2-0ubuntu0.13.10.2", rls:"UBUNTU13.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU13.04")
{

  if ((res = isdpkgvuln(pkg:"firefox", ver:"26.0+build2-0ubuntu0.13.04.2", rls:"UBUNTU13.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
