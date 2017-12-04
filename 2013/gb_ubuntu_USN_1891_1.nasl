###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1891_1.nasl 7958 2017-12-01 06:47:47Z santu $
#
# Ubuntu Update for thunderbird USN-1891-1
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_insight = "Multiple memory safety issues were discovered in Thunderbird. If the user
  were tricked into opening a specially crafted message with scripting
  enabled, an attacker could possibly exploit these to cause a denial of
  service via application crash, or potentially execute arbitrary code with
  the privileges of the user invoking Thunderbird. (CVE-2013-1682)

  Abhishek Arya discovered multiple use-after-free bugs. If the user were
  tricked into opening a specially crafted message with scripting enabled,
  an attacker could possibly exploit these to execute arbitrary code with
  the privileges of the user invoking Thunderbird. (CVE-2013-1684,
  CVE-2013-1685, CVE-2013-1686)

  Mariusz Mlynski discovered that user defined code within the XBL scope of
  an element could be made to bypass System Only Wrappers (SOW). If a user
  had scripting enabled, an attacker could potentially exploit this to
  execute arbitrary code with the privileges of the user invoking
  Thunderbird. (CVE-2013-1687)

  A crash was discovered when reloading a page that contained content using
  the onreadystatechange event. If a user had scripting enabled, an attacker
  could potentially exploit this to execute arbitrary code with the
  privileges of the user invoking Thunderbird. (CVE-2013-1690)

  Johnathan Kuskos discovered that Thunderbird sent data in the body of
  XMLHttpRequest HEAD requests. If a user had scripting enabled, an attacker
  could exploit this to conduct Cross-Site Request Forgery (CSRF) attacks.
  (CVE-2013-1692)

  Paul Stone discovered a timing flaw in the processing of SVG images with
  filters. If a user had scripting enabled, an attacker could exploit this
  to view sensitive information. (CVE-2013-1693)

  Boris Zbarsky discovered a flaw in PreserveWrapper. If a user had
  scripting enabled, an attacker could potentially exploit this to cause
  a denial of service via application crash, or execute code with the
  privileges of the user invoking Thunderbird. (CVE-2013-1694)

  It was discovered that XrayWrappers could be bypassed to call
  content-defined methods in certain circumstances. If a user had scripting
  enabled, an attacker could exploit this to cause undefined behaviour.
  (CVE-2013-1697)";


tag_affected = "thunderbird on Ubuntu 13.04 ,
  Ubuntu 12.10 ,
  Ubuntu 12.04 LTS";
tag_solution = "Please Install the Updated Packages.";

if(description)
{
  script_id(841489);
  script_version("$Revision: 7958 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 07:47:47 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2013-06-27 10:01:25 +0530 (Thu, 27 Jun 2013)");
  script_cve_id("CVE-2013-1682", "CVE-2013-1684", "CVE-2013-1685", "CVE-2013-1686",
                "CVE-2013-1687", "CVE-2013-1690", "CVE-2013-1692", "CVE-2013-1693",
                "CVE-2013-1694", "CVE-2013-1697");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Ubuntu Update for thunderbird USN-1891-1");

  script_xref(name: "USN", value: "1891-1");
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-1891-1/");
  script_summary("Check for the Version of thunderbird");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages");
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

  if ((res = isdpkgvuln(pkg:"thunderbird", ver:"17.0.7+build1-0ubuntu0.12.04.1", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU12.10")
{

  if ((res = isdpkgvuln(pkg:"thunderbird", ver:"17.0.7+build1-0ubuntu0.12.1", rls:"UBUNTU12.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU13.04")
{

  if ((res = isdpkgvuln(pkg:"thunderbird", ver:"17.0.7+build1-0ubuntu0.13.0", rls:"UBUNTU13.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
