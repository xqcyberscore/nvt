###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1222_1.nasl 7964 2017-12-01 07:32:11Z santu $
#
# Ubuntu Update for firefox USN-1222-1
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
tag_insight = "Benjamin Smedberg, Bob Clary, Jesse Ruderman, Bob Clary, Andrew McCreight,
  Andreas Gal, Gary Kwong, Igor Bukanov, Jason Orendorff, Jesse Ruderman, and
  Marcia Knous discovered multiple memory vulnerabilities in the browser
  rendering engine. An attacker could use these to possibly execute arbitrary
  code with the privileges of the user invoking Firefox. (CVE-2011-2995,
  CVE-2011-2997)

  Boris Zbarsky discovered that a frame named &quot;location&quot; could shadow the
  window.location object unless a script in a page grabbed a reference to the
  true object before the frame was created. This is in violation of the Same
  Origin Policy. A malicious website could possibly use this to access
  another website or the local file system. (CVE-2011-2999)
  
  Ian Graham discovered that when multiple Location headers were present,
  Firefox would use the second one resulting in a possible CRLF injection
  attack. CRLF injection issues can result in a wide variety of attacks, such
  as XSS (Cross-Site Scripting) vulnerabilities, browser cache poisoning, and
  cookie theft. (CVE-2011-3000)
  
  Mariusz Mlynski discovered that if the user could be convinced to hold down
  the enter key, a malicious website could potential pop up a download dialog
  and the default open action would be selected or lead to the installation
  of an arbitrary add-on. This would result in potentially malicious content
  being run with privileges of the user invoking Firefox. (CVE-2011-2372,
  CVE-2011-3001)
  
  Michael Jordon and Ben Hawkes discovered flaws in WebGL. If a user were
  tricked into opening a malicious page, an attacker could cause the browser
  to crash. (CVE-2011-3002, CVE-2011-3003)
  
  It was discovered that Firefox did not properly free memory when processing
  ogg files. If a user were tricked into opening a malicious page, an
  attacker could cause the browser to crash. (CVE-2011-3005)
  
  David Rees and Aki Helin discovered a problems in the JavaScript engine. An
  attacker could exploit this to crash the browser or potentially escalate
  privileges within the browser. (CVE-2011-3232)";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-1222-1";
tag_affected = "firefox on Ubuntu 11.04";
tag_solution = "Please Install the Updated Packages.";


if(description)
{
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-1222-1/");
  script_id(840759);
  script_version("$Revision: 7964 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 08:32:11 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2011-09-30 16:02:57 +0200 (Fri, 30 Sep 2011)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name: "USN", value: "1222-1");
  script_cve_id("CVE-2011-2995", "CVE-2011-2997", "CVE-2011-2999", "CVE-2011-3000", "CVE-2011-2372", "CVE-2011-3001", "CVE-2011-3002", "CVE-2011-3003", "CVE-2011-3005", "CVE-2011-3232", "CVE-2011-3004");
  script_name("Ubuntu Update for firefox USN-1222-1");

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

  if ((res = isdpkgvuln(pkg:"firefox", ver:"7.0.1+build1+nobinonly-0ubuntu0.11.04.1", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
