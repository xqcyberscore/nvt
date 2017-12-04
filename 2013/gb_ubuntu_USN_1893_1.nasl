###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1893_1.nasl 7958 2017-12-01 06:47:47Z santu $
#
# Ubuntu Update for subversion USN-1893-1
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
tag_insight = "Alexander Klink discovered that the Subversion mod_dav_svn module for
  Apache did not properly handle a large number of properties. A remote
  authenticated attacker could use this flaw to cause memory consumption,
  leading to a denial of service. (CVE-2013-1845)

  Ben Reser discovered that the Subversion mod_dav_svn module for
  Apache did not properly handle certain LOCKs. A remote authenticated
  attacker could use this flaw to cause Subversion to crash, leading to a
  denial of service. (CVE-2013-1846)

  Philip Martin and Ben Reser discovered that the Subversion mod_dav_svn
  module for Apache did not properly handle certain LOCKs. A remote
  attacker could use this flaw to cause Subversion to crash, leading to a
  denial of service. (CVE-2013-1847)

  It was discovered that the Subversion mod_dav_svn module for Apache did not
  properly handle certain PROPFIND requests. A remote attacker could use this
  flaw to cause Subversion to crash, leading to a denial of service.
  (CVE-2013-1849)

  Greg McMullin, Stefan Fuhrmann, Philip Martin, and Ben Reser discovered
  that the Subversion mod_dav_svn module for Apache did not properly handle
  certain log REPORT requests. A remote attacker could use this flaw to cause
  Subversion to crash, leading to a denial of service. This issue only
  affected Ubuntu 12.10 and Ubuntu 13.04. (CVE-2013-1884)

  Stefan Sperling discovered that Subversion incorrectly handled newline
  characters in filenames. A remote authenticated attacker could use this
  flaw to corrupt FSFS repositories. (CVE-2013-1968)

  Boris Lytochkin discovered that Subversion incorrectly handled TCP
  connections that were closed early. A remote attacker could use this flaw
  to cause Subversion to crash, leading to a denial of service.
  (CVE-2013-2112)";


tag_affected = "subversion on Ubuntu 13.04 ,
  Ubuntu 12.10 ,
  Ubuntu 12.04 LTS";
tag_solution = "Please Install the Updated Packages.";

if(description)
{
  script_id(841492);
  script_version("$Revision: 7958 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 07:47:47 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2013-07-02 10:20:46 +0530 (Tue, 02 Jul 2013)");
  script_cve_id("CVE-2013-1845", "CVE-2013-1846", "CVE-2013-1847", "CVE-2013-1849",
                "CVE-2013-1884", "CVE-2013-1968", "CVE-2013-2112");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_name("Ubuntu Update for subversion USN-1893-1");

  script_xref(name: "USN", value: "1893-1");
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-1893-1/");
  script_summary("Check for the Version of subversion");
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

  if ((res = isdpkgvuln(pkg:"libapache2-svn", ver:"1.6.17dfsg-3ubuntu3.3", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libsvn1", ver:"1.6.17dfsg-3ubuntu3.3", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU12.10")
{

  if ((res = isdpkgvuln(pkg:"libapache2-svn", ver:"1.7.5-1ubuntu2", rls:"UBUNTU12.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libsvn1:i386", ver:"1.7.5-1ubuntu2", rls:"UBUNTU12.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU13.04")
{

  if ((res = isdpkgvuln(pkg:"libapache2-svn", ver:"1.7.5-1ubuntu3", rls:"UBUNTU13.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libsvn1:i386 ", ver:"1.7.5-1ubuntu3", rls:"UBUNTU13.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
