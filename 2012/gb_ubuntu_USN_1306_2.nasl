###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1306_2.nasl 7960 2017-12-01 06:58:16Z santu $
#
# Ubuntu Update for mozvoikko USN-1306-2
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
tag_insight = "USN-1306-1 fixed vulnerabilities in Firefox. This update provides updated
  Mozvoikko and ubufox packages for use with Firefox 9.

  Original advisory details:
  Alexandre Poirot, Chris Blizzard, Kyle Huey, Scoobidiver, Christian Holler,
  David Baron, Gary Kwong, Jim Blandy, Bob Clary, Jesse Ruderman, Marcia
  Knous, and Rober Longson discovered several memory safety issues which
  could possibly be exploited to crash Firefox or execute arbitrary code as
  the user that invoked Firefox. (CVE-2011-3660)

  Aki Helin discovered a crash in the YARR regular expression library that
  could be triggered by javascript in web content. (CVE-2011-3661)

  It was discovered that a flaw in the Mozilla SVG implementation could
  result in an out-of-bounds memory access if SVG elements were removed
  during a DOMAttrModified event handler. An attacker could potentially
  exploit this vulnerability to crash Firefox. (CVE-2011-3658)

  Mario Heiderich discovered it was possible to use SVG animation accessKey
  events to detect key strokes even when JavaScript was disabled. A malicious
  web page could potentially exploit this to trick a user into interacting
  with a prompt thinking it came from the browser in a context where the user
  believed scripting was disabled. (CVE-2011-3663)

  It was discovered that it was possible to crash Firefox when scaling an OGG
  &lt;video&gt; element to extreme sizes. (CVE-2011-3665)";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-1306-2";
tag_affected = "mozvoikko on Ubuntu 11.04";
tag_solution = "Please Install the Updated Packages.";


if(description)
{
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-1306-2/");
  script_id(840859);
  script_version("$Revision: 7960 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 07:58:16 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2012-01-09 13:30:14 +0530 (Mon, 09 Jan 2012)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name: "USN", value: "1306-2");
  script_cve_id("CVE-2011-3660", "CVE-2011-3661", "CVE-2011-3658", "CVE-2011-3663", "CVE-2011-3665");
  script_name("Ubuntu Update for mozvoikko USN-1306-2");

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

if(release == "UBUNTU11.04")
{

  if ((res = isdpkgvuln(pkg:"xul-ext-mozvoikko", ver:"1.10.0-0ubuntu0.11.04.4", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xul-ext-ubufox", ver:"0.9.3-0ubuntu0.11.04.1", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
