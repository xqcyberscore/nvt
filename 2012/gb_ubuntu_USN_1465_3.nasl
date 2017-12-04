###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1465_3.nasl 7960 2017-12-01 06:58:16Z santu $
#
# Ubuntu Update for ubuntuone-client USN-1465-3
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
tag_insight = "USN-1465-1 fixed vulnerabilities in Ubuntu One Client. The update failed to
  install on certain Ubuntu 10.04 LTS systems that had a legacy Python 2.5
  package installed. This update fixes the problem.

  We apologize for the inconvenience.

  Original advisory details:

  It was discovered that the Ubuntu One Client incorrectly validated server
  certificates when using HTTPS connections. If a remote attacker were able
  to perform a man-in-the-middle attack, this flaw could be exploited to
  alter or compromise confidential information.";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-1465-3";
tag_affected = "ubuntuone-client on Ubuntu 10.04 LTS";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-1465-3/");
  script_id(841027);
  script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_version("$Revision: 7960 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 07:58:16 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2012-06-08 10:13:54 +0530 (Fri, 08 Jun 2012)");
  script_cve_id("CVE-2011-4409");
  script_xref(name: "USN", value: "1465-3");
  script_name("Ubuntu Update for ubuntuone-client USN-1465-3");

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

if(release == "UBUNTU10.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"python-ubuntuone-client", ver:"1.2.2-0ubuntu2.3", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
