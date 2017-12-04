###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1355_2.nasl 7960 2017-12-01 06:58:16Z santu $
#
# Ubuntu Update for mozvoikko USN-1355-2
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
tag_insight = "USN-1355-1 fixed vulnerabilities in Firefox. This update provides an
  updated Mozvoikko package for use with the latest Firefox.

  Original advisory details:
  It was discovered that if a user chose to export their Firefox Sync key
  the file is saved with incorrect permissions, making the file contents
  potentially readable by other users. (CVE-2012-0450)
  
  Nicolas Gregoire and Aki Helin discovered that when processing a malformed
  embedded XSLT stylesheet, Firefox can crash due to memory corruption. If
  the user were tricked into opening a specially crafted page, an attacker
  could exploit this to cause a denial of service via application crash, or
  potentially execute code with the privileges of the user invoking Firefox.
  (CVE-2012-0449)
  
  It was discovered that memory corruption could occur during the decoding of
  Ogg Vorbis files. If the user were tricked into opening a specially crafted
  file, an attacker could exploit this to cause a denial of service via
  application crash, or potentially execute code with the privileges of the
  user invoking Firefox. (CVE-2012-0444)
  
  Tim Abraldes discovered that when encoding certain images types the
  resulting data was always a fixed size. There is the possibility of
  sensitive data from uninitialized memory being appended to these images.
  (CVE-2012-0447)
  
  It was discovered that Firefox did not properly perform XPConnect security
  checks. An attacker could exploit this to conduct cross-site scripting
  (XSS) attacks through web pages and Firefox extensions. With cross-site
  scripting vulnerabilities, if a user were tricked into viewing a specially
  crafted page, a remote attacker could exploit this to modify the contents,
  or steal confidential data, within the same domain. (CVE-2012-0446)
  
  It was discovered that Firefox did not properly handle node removal in the
  DOM. If the user were tricked into opening a specially crafted page, an
  attacker could exploit this to cause a denial of service via application
  crash, or potentially execute code with the privileges of the user invoking
  Firefox. (CVE-2011-3659)
  
  Alex Dvorov discovered that Firefox did not properly handle sub-frames in
  form submissions. An attacker could exploit this to conduct phishing
  attacks using HTML5 frames. (CVE-2012-0445)
  
  Ben Hawkes, Christian Holler, Honza Bombas, Jason Orendorff, Jesse
  Ruderman, Jan Odvarko, Peter Van Der Beken, Bob Clary, and Bill McCloskey
  discovered memory safety issues affecting Firefox. If the user were tricked
 ... 

  Description truncated, for more information please check the Reference URL";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-1355-2";
tag_affected = "mozvoikko on Ubuntu 11.04 ,
  Ubuntu 10.10 ,
  Ubuntu 10.04 LTS";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-1355-2/");
  script_id(840886);
  script_version("$Revision: 7960 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 07:58:16 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2012-02-06 12:40:22 +0530 (Mon, 06 Feb 2012)");
  script_cve_id("CVE-2012-0450", "CVE-2012-0449", "CVE-2012-0444", "CVE-2012-0447",
                "CVE-2012-0446", "CVE-2011-3659", "CVE-2012-0445", "CVE-2012-0442",
                "CVE-2012-0443");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name: "USN", value: "1355-2");
  script_name("Ubuntu Update for mozvoikko USN-1355-2");

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

if(release == "UBUNTU10.10")
{

  if ((res = isdpkgvuln(pkg:"xul-ext-mozvoikko", ver:"2.0.1-0ubuntu0.10.10.1", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU10.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"xul-ext-mozvoikko", ver:"2.0.1-0ubuntu0.10.04.1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU11.04")
{

  if ((res = isdpkgvuln(pkg:"xul-ext-mozvoikko", ver:"2.0.1-0ubuntu0.11.04.1", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
