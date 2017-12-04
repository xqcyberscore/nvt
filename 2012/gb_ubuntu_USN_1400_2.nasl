###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1400_2.nasl 7960 2017-12-01 06:58:16Z santu $
#
# Ubuntu Update for ubufox USN-1400-2
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
tag_insight = "USN-1400-1 fixed vulnerabilities in Firefox. This update provides an
  updated ubufox package for use with the latest Firefox.

  Original advisory details:

  Soroush Dalili discovered that Firefox did not adequately protect against
  dropping JavaScript links onto a frame. A remote attacker could, through
  cross-site scripting (XSS), exploit this to modify the contents or steal
  confidential data. (CVE-2012-0455)

  Atte Kettunen discovered a use-after-free vulnerability in Firefox's
  handling of SVG animations. An attacker could potentially exploit this to
  execute arbitrary code with the privileges of the user invoking Firefox.
  (CVE-2012-0457)

  Atte Kettunen discovered an out of bounds read vulnerability in Firefox's
  handling of SVG Filters. An attacker could potentially exploit this to make
  data from the user's memory accessible to the page content. (CVE-2012-0456)

  Mike Brooks discovered that using carriage return line feed (CRLF)
  injection, one could introduce a new Content Security Policy (CSP) rule
  which allows for cross-site scripting (XSS) on sites with a separate header
  injection vulnerability. With cross-site scripting vulnerabilities, if a
  user were tricked into viewing a specially crafted page, a remote attacker
  could exploit this to modify the contents, or steal confidential data,
  within the same domain. (CVE-2012-0451)

  Mariusz Mlynski discovered that the Home button accepted JavaScript links
  to set the browser Home page. An attacker could use this vulnerability to
  get the script URL loaded in the privileged about:sessionrestore context.
  (CVE-2012-0458)

  Daniel Glazman discovered that the Cascading Style Sheets (CSS)
  implementation is vulnerable to crashing due to modification of a keyframe
  followed by access to the cssText of the keyframe. If the user were tricked
  into opening a specially crafted web page, an attacker could exploit this
  to cause a denial of service via application crash, or potentially execute
  code with the privileges of the user invoking Firefox. (CVE-2012-0459)

  Matt Brubeck discovered that Firefox did not properly restrict access to
  the window.fullScreen object. If the user were tricked into opening a
  specially crafted web page, an attacker could potentially use this
  vulnerability to spoof the user interface. (CVE-2012-0460)

  Bob Clary, Christian Holler, Jesse Ruderman, Nils, Michael Bebenita,
  Dindog, David Anderson, Jeff Walden, Vincenzo Iozzo, and Willem Pinckaers
  discovered memory safety issues affecting Firefox. If the us ...

  Description truncated, for more information please check the Reference URL";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-1400-2";
tag_affected = "ubufox on Ubuntu 11.10 ,
  Ubuntu 11.04 ,
  Ubuntu 10.10 ,
  Ubuntu 10.04 LTS";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-1400-2/");
  script_id(840955);
  script_version("$Revision: 7960 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 07:58:16 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2012-03-19 13:15:01 +0530 (Mon, 19 Mar 2012)");
  script_cve_id("CVE-2012-0455", "CVE-2012-0457", "CVE-2012-0456", "CVE-2012-0451",
                "CVE-2012-0458", "CVE-2012-0459", "CVE-2012-0460", "CVE-2012-0461",
                "CVE-2012-0462", "CVE-2012-0464");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_xref(name: "USN", value: "1400-2");
  script_name("Ubuntu Update for ubufox USN-1400-2");

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

  if ((res = isdpkgvuln(pkg:"xul-ext-ubufox", ver:"0.9.4-0ubuntu0.10.10.1", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU10.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"xul-ext-ubufox", ver:"0.9.4-0ubuntu0.10.04.1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU11.10")
{

  if ((res = isdpkgvuln(pkg:"xul-ext-ubufox", ver:"1.0.3-0ubuntu1", rls:"UBUNTU11.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU11.04")
{

  if ((res = isdpkgvuln(pkg:"xul-ext-ubufox", ver:"0.9.4-0ubuntu1", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
