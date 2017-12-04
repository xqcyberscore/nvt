###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1213_1.nasl 7964 2017-12-01 07:32:11Z santu $
#
# Ubuntu Update for thunderbird USN-1213-1
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_insight = "Benjamin Smedberg, Bob Clary, Jesse Ruderman, and Josh Aas discovered
  multiple memory vulnerabilities in the Gecko rendering engine. An
  attacker could use these to possibly execute arbitrary code with the
  privileges of the user invoking Thunderbird. (CVE-2011-2995, CVE-2011-2996)

  Boris Zbarsky discovered that a frame named &quot;location&quot; could shadow the
  window.location object unless a script in a page grabbed a reference to the
  true object before the frame was created. This is in violation of the Same
  Origin Policy. A malicious E-Mail could possibly use this to access the
  local file system. (CVE-2011-2999)
  
  Mark Kaplan discovered an integer underflow in the SpiderMonkey JavaScript
  engine. An attacker could potentially use this to crash Thunderbird.
  
  Ian Graham discovered that when multiple Location headers were present,
  Thunderbird would use the second one resulting in a possible CRLF injection
  attack. CRLF injection issues can result in a wide variety of attacks, such
  as XSS (Cross-Site Scripting) vulnerabilities, browser cache poisoning, and
  cookie theft. (CVE-2011-3000)
  
  Mariusz Mlynski discovered that if the user could be convinced to hold down
  the enter key, a malicious website or E-Mail could potential pop up a
  download dialog and the default open action would be selected. This would
  result in potentially malicious content being run with privileges of the
  user invoking Thunderbird. (CVE-2011-2372)";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-1213-1";
tag_affected = "thunderbird on Ubuntu 11.04 ,
  Ubuntu 10.10 ,
  Ubuntu 10.04 LTS";
tag_solution = "Please Install the Updated Packages.";


if(description)
{
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-1213-1/");
  script_id(840754);
  script_version("$Revision: 7964 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 08:32:11 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2011-09-30 16:02:57 +0200 (Fri, 30 Sep 2011)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name: "USN", value: "1213-1");
  script_cve_id("CVE-2011-2995", "CVE-2011-2996", "CVE-2011-2999", "CVE-2011-3000", "CVE-2011-2372");
  script_name("Ubuntu Update for thunderbird USN-1213-1");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
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

  if ((res = isdpkgvuln(pkg:"thunderbird", ver:"3.1.15+build1+nobinonly-0ubuntu0.10.10.1", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU10.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"thunderbird", ver:"3.1.15+build1+nobinonly-0ubuntu0.10.04.1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU11.04")
{

  if ((res = isdpkgvuln(pkg:"thunderbird", ver:"3.1.15+build1+nobinonly-0ubuntu0.11.04.1", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
