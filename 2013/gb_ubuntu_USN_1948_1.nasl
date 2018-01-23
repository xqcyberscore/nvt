###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1948_1.nasl 8494 2018-01-23 06:57:55Z teissa $
#
# Ubuntu Update for python-httplib2 USN-1948-1
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
  script_id(841551);
  script_version("$Revision: 8494 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-23 07:57:55 +0100 (Tue, 23 Jan 2018) $");
  script_tag(name:"creation_date", value:"2013-09-12 11:49:03 +0530 (Thu, 12 Sep 2013)");
  script_cve_id("CVE-2013-2037");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");
  script_name("Ubuntu Update for python-httplib2 USN-1948-1");

  tag_insight = "It was discovered that httplib2 only validated SSL certificates on the
first request to a connection, and didn't report validation failures on
subsequent requests. If a remote attacker were able to perform a
man-in-the-middle attack, this flaw could possibly be exploited in certain
scenarios to alter or compromise confidential information in applications
that used the httplib2 library.";

  tag_affected = "python-httplib2 on Ubuntu 13.04 ,
  Ubuntu 12.10 ,
  Ubuntu 12.04 LTS ,
  Ubuntu 10.04 LTS";

  tag_solution = "Please Install the Updated Packages.";


  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name: "USN", value: "1948-1");
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-1948-1/");
  script_tag(name: "summary" , value: "Check for the Version of python-httplib2");
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

if(release == "UBUNTU12.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"python-httplib2", ver:"0.7.2-1ubuntu2.1", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU10.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"python-httplib2", ver:"0.7.2-1ubuntu2~0.10.04.2", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU12.10")
{

  if ((res = isdpkgvuln(pkg:"python-httplib2", ver:"0.7.4-2ubuntu0.1", rls:"UBUNTU12.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU13.04")
{

  if ((res = isdpkgvuln(pkg:"python-httplib2", ver:"0.7.7-1ubuntu0.1", rls:"UBUNTU13.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
