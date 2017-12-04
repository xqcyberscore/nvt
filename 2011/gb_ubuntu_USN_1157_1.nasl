###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1157_1.nasl 7964 2017-12-01 07:32:11Z santu $
#
# Ubuntu Update for firefox USN-1157-1
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
tag_insight = "Bob Clary, Kevin Brosnan, Gary Kwong, Jesse Ruderman, Christian Biesinger,
  Bas Schouten, Igor Bukanov, Bill McCloskey, Olli Pettay, Daniel Veditz and
  Marcia Knous discovered multiple memory vulnerabilities in the browser
  rendering engine. An attacker could possibly execute arbitrary code with
  the privileges of the user invoking Firefox. (CVE-2011-2374, CVE-2011-2375)

  Martin Barbella discovered that under certain conditions, viewing a XUL
  document while JavaScript was disabled caused deleted memory to be
  accessed. An attacker could potentially use this to crash Firefox or
  execute arbitrary code with the privileges of the user invoking Firefox.
  (CVE-2011-2373)
  
  Jordi Chancel discovered a vulnerability on multipart/x-mixed-replace
  images due to memory corruption. An attacker could potentially use this to
  crash Firefox or execute arbitrary code with the privileges of the user
  invoking Firefox. (CVE-2011-2377)
  
  Chris Rohlf and Yan Ivnitskiy discovered an integer overflow vulnerability
  in JavaScript Arrays. An attacker could potentially use this to execute
  arbitrary code with the privileges of the user invoking Firefox.
  (CVE-2011-2371)
  
  It was discovered that Firefox's WebGL textures did not honor same-origin
  policy. If a user were tricked into viewing a malicious site, an attacker
  could potentially view image data from a different site. (CVE-2011-2366)
  
  Christoph Diehl discovered an out-of-bounds read vulnerability in WebGL
  code. An attacker could potentially read data that other processes had
  stored in the GPU. (CVE-2011-2367)
  
  Christoph Diehl discovered an invalid write vulnerability in WebGL code. An
  attacker could potentially use this to execute arbitrary code with the
  privileges of the user invoking Firefox. (CVE-2011-2368)
  
  It was discovered that an unauthorized site could trigger an installation
  dialog for addons and themes. If a user were tricked into viewing a
  malicious site, an attacker could possibly trick the user into installing a
  malicious addon or theme. (CVE-2011-2370)
  
  Mario Heiderich discovered a vulnerability in displaying decoded
  HTML-encoded entities inside SVG elements. An attacker could utilize this
  to perform cross-site scripting attacks. (CVE-2011-2369)";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-1157-1";
tag_affected = "firefox on Ubuntu 11.04";
tag_solution = "Please Install the Updated Packages.";


if(description)
{
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-1157-1/");
  script_id(840687);
  script_version("$Revision: 7964 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 08:32:11 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2011-06-24 16:46:35 +0200 (Fri, 24 Jun 2011)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name: "USN", value: "1157-1");
  script_cve_id("CVE-2011-2374", "CVE-2011-2375", "CVE-2011-2373", "CVE-2011-2377", "CVE-2011-2371", "CVE-2011-2366", "CVE-2011-2367", "CVE-2011-2368", "CVE-2011-2370", "CVE-2011-2369");
  script_name("Ubuntu Update for firefox USN-1157-1");

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

if(release == "UBUNTU11.04")
{

  if ((res = isdpkgvuln(pkg:"firefox", ver:"5.0+build1+nobinonly-0ubuntu0.11.04.1", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
