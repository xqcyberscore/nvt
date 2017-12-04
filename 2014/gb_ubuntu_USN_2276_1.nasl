###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_2276_1.nasl 7957 2017-12-01 06:40:08Z santu $
#
# Ubuntu Update for php5 USN-2276-1
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
  script_oid("1.3.6.1.4.1.25623.1.0.841890");
  script_version("$Revision: 7957 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 07:40:08 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2014-07-15 16:41:08 +0530 (Tue, 15 Jul 2014)");
  script_cve_id("CVE-2014-0207", "CVE-2014-3478", "CVE-2014-3479", "CVE-2014-3480",
                "CVE-2014-3487", "CVE-2014-3515", "CVE-2014-4670", "CVE-2014-4698",
                "CVE-2014-4721");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Ubuntu Update for php5 USN-2276-1");

  tag_insight = "Francisco Alonso discovered that the PHP Fileinfo component
incorrectly handled certain CDF documents. A remote attacker could use this
issue to cause PHP to hang or crash, resulting in a denial of service.
(CVE-2014-0207, CVE-2014-3478, CVE-2014-3479, CVE-2014-3480, CVE-2014-3487)

Stefan Esser discovered that PHP incorrectly handled unserializing SPL
extension objects. An attacker could use this issue to execute arbitrary
code. (CVE-2014-3515)

It was discovered that PHP incorrectly handled certain SPL Iterators. An
attacker could use this issue to cause PHP to crash, resulting in a denial
of service. (CVE-2014-4670)

It was discovered that PHP incorrectly handled certain ArrayIterators. An
attacker could use this issue to cause PHP to crash, resulting in a denial
of service. (CVE-2014-4698)

Stefan Esser discovered that PHP incorrectly handled variable types when
calling phpinfo(). An attacker could use this issue to possibly gain access
to arbitrary memory, possibly containing sensitive information.
(CVE-2014-4721)";

  tag_affected = "php5 on Ubuntu 14.04 LTS ,
  Ubuntu 13.10 ,
  Ubuntu 12.04 LTS ,
  Ubuntu 10.04 LTS";

  tag_solution = "Please Install the Updated Packages.";


  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name: "USN", value: "2276-1");
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-2276-1/");
  script_summary("Check for the Version of php5");
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

if(release == "UBUNTU14.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libapache2-mod-php5", ver:"5.5.9+dfsg-1ubuntu4.3", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"php5-cgi", ver:"5.5.9+dfsg-1ubuntu4.3", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"php5-cli", ver:"5.5.9+dfsg-1ubuntu4.3", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"php5-fpm", ver:"5.5.9+dfsg-1ubuntu4.3", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU12.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libapache2-mod-php5", ver:"5.3.10-1ubuntu3.13", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"php5-cgi", ver:"5.3.10-1ubuntu3.13", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"php5-cli", ver:"5.3.10-1ubuntu3.13", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"php5-fpm", ver:"5.3.10-1ubuntu3.13", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU10.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libapache2-mod-php5", ver:"5.3.2-1ubuntu4.26", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"php5-cgi", ver:"5.3.2-1ubuntu4.26", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"php5-cli", ver:"5.3.2-1ubuntu4.26", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU13.10")
{

  if ((res = isdpkgvuln(pkg:"libapache2-mod-php5", ver:"5.5.3+dfsg-1ubuntu2.6", rls:"UBUNTU13.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"php5-cgi", ver:"5.5.3+dfsg-1ubuntu2.6", rls:"UBUNTU13.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"php5-cli", ver:"5.5.3+dfsg-1ubuntu2.6", rls:"UBUNTU13.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"php5-fpm", ver:"5.5.3+dfsg-1ubuntu2.6", rls:"UBUNTU13.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
