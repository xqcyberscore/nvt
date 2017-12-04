###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_2243_1.nasl 7957 2017-12-01 06:40:08Z santu $
#
# Ubuntu Update for firefox USN-2243-1
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
  script_oid("1.3.6.1.4.1.25623.1.0.841855");
  script_version("$Revision: 7957 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 07:40:08 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2014-06-17 10:05:45 +0530 (Tue, 17 Jun 2014)");
  script_cve_id("CVE-2014-1533", "CVE-2014-1534", "CVE-2014-1536", "CVE-2014-1537",
                "CVE-2014-1538", "CVE-2014-1540", "CVE-2014-1541", "CVE-2014-1542");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Ubuntu Update for firefox USN-2243-1");

  tag_insight = "Gary Kwong, Christoph Diehl, Christian Holler, Hannes Verschore,
Jan de Mooij, Ryan VanderMeulen, Jeff Walden, Kyle Huey, Jesse Ruderman, Gregor
Wagner, Benoit Jacob and Karl Tomlinson discovered multiple memory safety
issues in Firefox. If a user were tricked in to opening a specially
crafted website, an attacker could potentially exploit these to cause a
denial of service via application crash, or execute arbitrary code with
the privileges of the user invoking Firefox. (CVE-2014-1533,
CVE-2014-1534)

Abhishek Arya discovered multiple use-after-free and out-of-bounds read
issues in Firefox. An attacker could potentially exploit these to cause
a denial of service via application crash or execute arbitrary code with
the priviliges of the user invoking Firefox. (CVE-2014-1536,
CVE-2014-1537, CVE-2014-1538)

Tyson Smith and Jesse Schwartzentruber discovered a use-after-free in the
event listener manager. An attacker could potentially exploit this to
cause a denial of service via application crash or execute arbitrary code
with the priviliges of the user invoking Firefox. (CVE-2014-1540)

A use-after-free was discovered in the SMIL animation controller. An
attacker could potentially exploit this to cause a denial of service via
application crash or execute arbitrary code with the priviliges of the
user invoking Firefox. (CVE-2014-1541)

Holger Fuhrmannek discovered a buffer overflow in Web Audio. An attacker
could potentially exploit this to cause a denial of service via
application crash or execute arbitrary code with the priviliges of the
user invoking Firefox. (CVE-2014-1542)";

  tag_affected = "firefox on Ubuntu 14.04 LTS ,
  Ubuntu 13.10 ,
  Ubuntu 12.04 LTS";

  tag_solution = "Please Install the Updated Packages.";


  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name: "USN", value: "2243-1");
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-2243-1/");
  script_summary("Check for the Version of firefox");
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

  if ((res = isdpkgvuln(pkg:"firefox", ver:"30.0+build1-0ubuntu0.14.04.3", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU12.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"firefox", ver:"30.0+build1-0ubuntu0.12.04.3", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU13.10")
{

  if ((res = isdpkgvuln(pkg:"firefox", ver:"30.0+build1-0ubuntu0.13.10.3", rls:"UBUNTU13.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
