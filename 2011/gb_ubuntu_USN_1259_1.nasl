###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1259_1.nasl 7964 2017-12-01 07:32:11Z santu $
#
# Ubuntu Update for apache2 USN-1259-1
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
tag_insight = "It was discovered that the mod_proxy module in Apache did not properly
  interact with the RewriteRule and ProxyPassMatch pattern matches
  in the configuration of a reverse proxy. This could allow remote
  attackers to contact internal webservers behind the proxy that were
  not intended for external exposure. (CVE-2011-3368)

  Stefano Nichele discovered that the mod_proxy_ajp module in Apache when
  used with mod_proxy_balancer in certain configurations could allow
  remote attackers to cause a denial of service via a malformed HTTP
  request. (CVE-2011-3348)

  Samuel Montosa discovered that the ITK Multi-Processing Module for
  Apache did not properly handle certain configuration sections that
  specify NiceValue but not AssignUserID, preventing Apache from dropping
  privileges correctly. This issue only affected Ubuntu 10.04 LTS, Ubuntu
  10.10 and Ubuntu 11.04. (CVE-2011-1176)

  USN 1199-1 fixed a vulnerability in the byterange filter of Apache. The
  upstream patch introduced a regression in Apache when handling specific
  byte range requests. This update fixes the issue.

  Original advisory details:

  A flaw was discovered in the byterange filter in Apache. A remote attacker
  could exploit this to cause a denial of service via resource exhaustion.";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-1259-1";
tag_affected = "apache2 on Ubuntu 11.04 ,
  Ubuntu 10.10 ,
  Ubuntu 10.04 LTS ,
  Ubuntu 8.04 LTS";
tag_solution = "Please Install the Updated Packages.";


if(description)
{
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-1259-1/");
  script_id(840798);
  script_version("$Revision: 7964 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 08:32:11 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2011-11-11 09:55:23 +0530 (Fri, 11 Nov 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_xref(name: "USN", value: "1259-1");
  script_cve_id("CVE-2011-3368", "CVE-2011-3348", "CVE-2011-1176");
  script_name("Ubuntu Update for apache2 USN-1259-1");

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

if(release == "UBUNTU10.10")
{

  if ((res = isdpkgvuln(pkg:"apache2-mpm-itk", ver:"2.2.16-1ubuntu3.4", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"apache2.2-bin", ver:"2.2.16-1ubuntu3.4", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU10.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"apache2-mpm-itk", ver:"2.2.14-5ubuntu8.7", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"apache2.2-bin", ver:"2.2.14-5ubuntu8.7", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU11.04")
{

  if ((res = isdpkgvuln(pkg:"apache2-mpm-itk", ver:"2.2.17-1ubuntu1.4", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"apache2.2-bin", ver:"2.2.17-1ubuntu1.4", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU8.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"apache2.2-common", ver:"2.2.8-1ubuntu0.22", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
