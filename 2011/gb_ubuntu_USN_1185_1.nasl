###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for thunderbird USN-1185-1
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
tag_insight = "Gary Kwong, Igor Bukanov, and Bob Clary discovered multiple memory
  vulnerabilities in the Gecko rendering engine. An attacker could use
  these to possibly execute arbitrary code with the privileges of the user
  invoking Thunderbird. (CVE-2011-2982)

  It was discovered that a vulnerability in event management code could
  permit JavaScript to be run in the wrong context. This could potentially
  allow a malicious website to run code as another website or with escalated
  privileges in a chrome-privileged context. (CVE-2011-2981)
  
  It was discovered that an SVG text manipulation routine contained a
  dangling pointer vulnerability. An attacker could potentially use this to
  crash Thunderbird or execute arbitrary code with the privileges of the user
  invoking Thunderbird. (CVE-2011-0084)
  
  It was discovered that web content could receive chrome privileges if it
  registered for drop events and a browser tab element was dropped into the
  content area. This could potentially allow a malicious website to run code
  with escalated privileges within Thunderbird. (CVE-2011-2984)
  
  It was discovered that appendChild contained a dangling pointer
  vulnerability. An attacker could potentially use this to crash Thunderbird
  or execute arbitrary code with the privileges of the user invoking
  Thunderbird. (CVE-2011-2378)
  
  It was discovered that data from other domains could be read when
  RegExp.input was set. This could potentially allow a malicious website
  access to private data from other domains. (CVE-2011-2983)";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-1185-1";
tag_affected = "thunderbird on Ubuntu 11.04 ,
  Ubuntu 10.10 ,
  Ubuntu 10.04 LTS";
tag_solution = "Please Install the Updated Packages.";


if(description)
{
  script_xref(name : "URL" , value : "https://lists.ubuntu.com/archives/ubuntu-security-announce/2011-August/001403.html");
  script_id(840731);
  script_version("$Revision: 3105 $");
  script_tag(name:"last_modification", value:"$Date: 2016-04-18 16:58:47 +0200 (Mon, 18 Apr 2016) $");
  script_tag(name:"creation_date", value:"2011-08-27 16:37:49 +0200 (Sat, 27 Aug 2011)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name: "USN", value: "1185-1");
  script_cve_id("CVE-2011-2982", "CVE-2011-2981", "CVE-2011-0084", "CVE-2011-2984", "CVE-2011-2378", "CVE-2011-2983");
  script_name("Ubuntu Update for thunderbird USN-1185-1");

  script_summary("Check for the Version of thunderbird");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
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

if(release == "UBUNTU10.10")
{

  if ((res = isdpkgvuln(pkg:"thunderbird", ver:"3.1.12+build1+nobinonly-0ubuntu0.10.10.1", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU10.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"thunderbird", ver:"3.1.12+build1+nobinonly-0ubuntu0.10.04.1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU11.04")
{

  if ((res = isdpkgvuln(pkg:"thunderbird", ver:"3.1.12+build1+nobinonly-0ubuntu0.11.04.1", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
