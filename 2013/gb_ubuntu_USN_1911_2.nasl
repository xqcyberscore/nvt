###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1911_2.nasl 7958 2017-12-01 06:47:47Z santu $
#
# Ubuntu Update for ghostscript USN-1911-2
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

if(description)
{
  script_id(841525);
  script_version("$Revision: 7958 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 07:47:47 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2013-08-08 11:48:17 +0530 (Thu, 08 Aug 2013)");
  script_cve_id("CVE-2013-4160");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Ubuntu Update for ghostscript USN-1911-2");

  tag_insight = "USN-1911-1 fixed vulnerabilities in Little CMS. This update provides the
corresponding updates for Ghostscript.

Original advisory details:

It was discovered that Little CMS did not properly verify certain memory
allocations. If a user or automated system using Little CMS were tricked
into opening a specially crafted file, an attacker could cause Little CMS
to crash.";

  tag_affected = "ghostscript on Ubuntu 13.04";

  tag_solution = "Please Install the Updated Packages.";


  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name: "USN", value: "1911-2");
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-1911-2/");
  script_summary("Check for the Version of ghostscript");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages");
  exit(0);
}


include("pkg-lib-deb.inc");

release = get_kb_item("ssh/login/release");

res = "";
if(release == NULL){
  exit(0);
}

if(release == "UBUNTU13.04")
{

  if ((res = isdpkgvuln(pkg:"libgs9", ver:"9.07~dfsg2-0ubuntu3.1", rls:"UBUNTU13.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
