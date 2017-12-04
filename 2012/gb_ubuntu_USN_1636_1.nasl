###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1636_1.nasl 7960 2017-12-01 06:58:16Z santu $
#
# Ubuntu Update for thunderbird USN-1636-1
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
tag_insight = "Gary Kwong, Jesse Ruderman, Christian Holler, Bob Clary, Kyle Huey, Ed
  Morley, Chris Lord, Boris Zbarsky, Julian Seward, Bill McCloskey, and
  Andrew McCreight discovered several memory corruption flaws in Thunderbird.
  If a user were tricked into opening a malicious website and had JavaScript
  enabled, an attacker could exploit these to execute arbitrary JavaScript
  code within the context of another website or arbitrary code as the user
  invoking the program. (CVE-2012-5842, CVE-2012-5843)

  Atte Kettunen discovered a buffer overflow while rendering GIF format
  images. An attacker could exploit this to possibly execute arbitrary code
  as the user invoking Thunderbird. (CVE-2012-4202)
  
  It was discovered that the evalInSandbox function's JavaScript sandbox
  context could be circumvented. An attacker could exploit this to perform a
  cross-site scripting (XSS) attack or steal a copy of a local file if the
  user has installed an add-on vulnerable to this attack. With cross-site
  scripting vulnerabilities, if a user were tricked into viewing a specially
  crafted page and had JavaScript enabled, a remote attacker could exploit
  this to modify the contents, or steal confidential data, within the same
  domain. (CVE-2012-4201)
  
  Jonathan Stephens discovered that combining vectors involving the setting
  of Cascading Style Sheets (CSS) properties in conjunction with SVG text
  could cause Thunderbird to crash. If a user were tricked into opening a
  malicious E-Mail, an attacker could cause a denial of service via
  application crash or execute arbitrary code with the privliges of the user
  invoking the program. (CVE-2012-5836)
  
  Scott Bell discovered a memory corruption issue in the JavaScript engine.
  If a user were tricked into opening a malicious website and had JavaScript
  enabled, an attacker could exploit this to execute arbitrary JavaScript
  code within the context of another website or arbitrary code as the user
  invoking the program. (CVE-2012-4204)
  
  Gabor Krizsanits discovered that XMLHttpRequest objects created within
  sandboxes have the system principal instead of the sandbox principal. This
  can lead to cross-site request forgery (CSRF) or information theft via an
  add-on running untrusted code in a sandbox. (CVE-2012-4205)
  
  Peter Van der Beken discovered XrayWrapper implementation in Firefox does
  not consider the compartment during property filtering. If JavaScript were
  enabled, an attacker could use this to bypass intended chrome-only
  restrictions on reading DOM object prope ... 

  Description truncated, for more information please check the Reference URL";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-1636-1";
tag_affected = "thunderbird on Ubuntu 12.10 ,
  Ubuntu 12.04 LTS ,
  Ubuntu 11.10 ,
  Ubuntu 10.04 LTS";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-1636-1/");
  script_id(841219);
  script_version("$Revision: 7960 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 07:58:16 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2012-11-23 11:50:54 +0530 (Fri, 23 Nov 2012)");
  script_cve_id("CVE-2012-5842", "CVE-2012-5843", "CVE-2012-4202", "CVE-2012-4201",
                "CVE-2012-5836", "CVE-2012-4204", "CVE-2012-4205", "CVE-2012-4208",
                "CVE-2012-5841", "CVE-2012-4207", "CVE-2012-4209", "CVE-2012-4214",
                "CVE-2012-4215", "CVE-2012-4216", "CVE-2012-5829", "CVE-2012-5839",
                "CVE-2012-5840", "CVE-2012-4212", "CVE-2012-4213", "CVE-2012-4217",
                "CVE-2012-4218", "CVE-2012-5830", "CVE-2012-5833", "CVE-2012-5835",
                "CVE-2012-5838");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name: "USN", value: "1636-1");
  script_name("Ubuntu Update for thunderbird USN-1636-1");

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

if(release == "UBUNTU12.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"thunderbird", ver:"17.0+build2-0ubuntu0.12.04.1", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU11.10")
{

  if ((res = isdpkgvuln(pkg:"thunderbird", ver:"17.0+build2-0ubuntu0.11.10.1", rls:"UBUNTU11.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU10.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"thunderbird", ver:"17.0+build2-0ubuntu0.10.04.1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU12.10")
{

  if ((res = isdpkgvuln(pkg:"thunderbird", ver:"17.0+build2-0ubuntu0.12.10.1", rls:"UBUNTU12.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
