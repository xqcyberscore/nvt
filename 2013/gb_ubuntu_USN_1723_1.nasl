###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1723_1.nasl 7958 2017-12-01 06:47:47Z santu $
#
# Ubuntu Update for qt4-x11 USN-1723-1
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
tag_insight = "Richard J. Moore and Peter Hartmann discovered that Qt allowed redirecting
  requests from http to file schemes. If an attacker were able to perform a
  man-in-the-middle attack, this flaw could be exploited to view sensitive
  information. This issue only affected Ubuntu 11.10, Ubuntu 12.04 LTS,
  and Ubuntu 12.10. (CVE-2012-5624)

  Stephen Cheng discovered that Qt may report incorrect errors when ssl
  certificate verification fails. (CVE-2012-6093)
  
  Tim Brown and Mark Lowe discovered that Qt incorrectly used weak
  permissions on shared memory segments. A local attacker could use this
  issue to view sensitive information, or modify program data belonging to
  other users. (CVE-2013-0254)";


tag_affected = "qt4-x11 on Ubuntu 12.10 ,
  Ubuntu 12.04 LTS ,
  Ubuntu 11.10 ,
  Ubuntu 10.04 LTS";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-1723-1/");
  script_id(841319);
  script_version("$Revision: 7958 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 07:47:47 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2013-02-15 11:25:30 +0530 (Fri, 15 Feb 2013)");
  script_cve_id("CVE-2012-5624", "CVE-2012-6093", "CVE-2013-0254");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_xref(name: "USN", value: "1723-1");
  script_name("Ubuntu Update for qt4-x11 USN-1723-1");

  script_summary("Check for the Version of qt4-x11");
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

  if ((res = isdpkgvuln(pkg:"libqt4-core", ver:"4:4.8.1-0ubuntu4.4", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libqt4-network", ver:"4:4.8.1-0ubuntu4.4", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU11.10")
{

  if ((res = isdpkgvuln(pkg:"libqt4-core", ver:"4:4.7.4-0ubuntu8.3", rls:"UBUNTU11.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libqt4-network", ver:"4:4.7.4-0ubuntu8.3", rls:"UBUNTU11.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU10.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libqt4-core", ver:"4:4.6.2-0ubuntu5.6", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libqt4-network", ver:"4:4.6.2-0ubuntu5.6", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU12.10")
{

  if ((res = isdpkgvuln(pkg:"libqt4-core", ver:"4:4.8.3+dfsg-0ubuntu3.1", rls:"UBUNTU12.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libqt4-network", ver:"4:4.8.3+dfsg-0ubuntu3.1", rls:"UBUNTU12.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
