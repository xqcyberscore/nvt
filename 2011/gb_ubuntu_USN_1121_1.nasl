###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1121_1.nasl 7964 2017-12-01 07:32:11Z santu $
#
# Ubuntu Update for firefox USN-1121-1
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
tag_insight = "Boris Zbarsky, Gary Kwong, Jesse Ruderman, Michael Wu, and Ted Mielczarek
  discovered multiple memory vulnerabilities. An attacker could exploit these
  to possibly run arbitrary code as the user running Firefox. (CVE-2011-0079)

  It was discovered that there was a vulnerability in the memory handling of
  certain types of content. An attacker could exploit this to possibly run
  arbitrary code as the user running Firefox. (CVE-2011-0081)
  
  It was discovered that Firefox incorrectly handled certain JavaScript
  requests. An attacker could exploit this to possibly run arbitrary code as
  the user running Firefox. (CVE-2011-0069)
  
  Ian Beer discovered a vulnerability in the memory handling of a certain
  types of documents. An attacker could exploit this to possibly run
  arbitrary code as the user running Firefox. (CVE-2011-0070)
  
  Chris Evans discovered a vulnerability in Firefox's XSLT generate-id()
  function. An attacker could possibly use this vulnerability to make other
  attacks more reliable. (CVE-2011-1202)";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-1121-1";
tag_affected = "firefox on Ubuntu 11.04";
tag_solution = "Please Install the Updated Packages.";


if(description)
{
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-1121-1/");
  script_id(840635);
  script_version("$Revision: 7964 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 08:32:11 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2011-05-10 14:04:15 +0200 (Tue, 10 May 2011)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name: "USN", value: "1121-1");
  script_cve_id("CVE-2011-0079", "CVE-2011-0081", "CVE-2011-0069", "CVE-2011-0070", "CVE-2011-1202");
  script_name("Ubuntu Update for firefox USN-1121-1");

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

  if ((res = isdpkgvuln(pkg:"firefox", ver:"4.0.1+build1+nobinonly-0ubuntu0.11.04.1", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
