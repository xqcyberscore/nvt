###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_2130_1.nasl 7957 2017-12-01 06:40:08Z santu $
#
# Ubuntu Update for tomcat7 USN-2130-1
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_id(841741);
  script_version("$Revision: 7957 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 07:40:08 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2014-03-12 09:38:22 +0530 (Wed, 12 Mar 2014)");
  script_cve_id("CVE-2013-4286", "CVE-2013-4322", "CVE-2014-0033", "CVE-2014-0050");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Ubuntu Update for tomcat7 USN-2130-1");

  tag_insight = "It was discovered that Tomcat incorrectly handled certain
inconsistent HTTP headers. A remote attacker could possibly use this flaw to
conduct request smuggling attacks. (CVE-2013-4286)

It was discovered that Tomcat incorrectly handled certain requests
submitted using chunked transfer encoding. A remote attacker could use this
flaw to cause the Tomcat server to stop responding, resulting in a denial
of service. (CVE-2013-4322)

It was discovered that Tomcat incorrectly applied the disableURLRewriting
setting when handling a session id in a URL. A remote attacker could
possibly use this flaw to conduct session fixation attacks. This issue
only applied to Ubuntu 12.04 LTS. (CVE-2014-0033)

It was discovered that Tomcat incorrectly handled malformed Content-Type
headers and multipart requests. A remote attacker could use this flaw to
cause the Tomcat server to stop responding, resulting in a denial of
service. This issue only applied to Ubuntu 12.10 and Ubuntu 13.10.
(CVE-2014-0050)";

  tag_affected = "tomcat7 on Ubuntu 13.10 ,
  Ubuntu 12.10 ,
  Ubuntu 12.04 LTS ,
  Ubuntu 10.04 LTS";

  tag_solution = "Please Install the Updated Packages.";


  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name: "USN", value: "2130-1");
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-2130-1/");
  script_summary("Check for the Version of tomcat7");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
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

  if ((res = isdpkgvuln(pkg:"libtomcat6-java", ver:"6.0.35-1ubuntu3.4", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU10.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libtomcat6-java", ver:"6.0.24-2ubuntu1.15", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU13.10")
{

  if ((res = isdpkgvuln(pkg:"libtomcat7-java", ver:"7.0.42-1ubuntu0.1", rls:"UBUNTU13.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU12.10")
{

  if ((res = isdpkgvuln(pkg:"libtomcat7-java", ver:"7.0.30-0ubuntu1.3", rls:"UBUNTU12.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
