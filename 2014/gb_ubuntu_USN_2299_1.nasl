###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_2299_1.nasl 7957 2017-12-01 06:40:08Z santu $
#
# Ubuntu Update for apache2 USN-2299-1
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
  script_oid("1.3.6.1.4.1.25623.1.0.841915");
  script_version("$Revision: 7957 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 07:40:08 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2014-07-28 16:41:33 +0530 (Mon, 28 Jul 2014)");
  script_cve_id("CVE-2014-0117", "CVE-2014-0118", "CVE-2014-0226", "CVE-2014-0231");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("Ubuntu Update for apache2 USN-2299-1");

  tag_insight = "Marek Kroemeke discovered that the mod_proxy module incorrectly
handled certain requests. A remote attacker could use this issue to cause the
server to stop responding, leading to a denial of service. This issue only
affected Ubuntu 14.04 LTS. (CVE-2014-0117)

Giancarlo Pellegrino and Davide Balzarotti discovered that the mod_deflate
module incorrectly handled body decompression. A remote attacker could use
this issue to cause resource consumption, leading to a denial of service.
(CVE-2014-0118)

Marek Kroemeke and others discovered that the mod_status module incorrectly
handled certain requests. A remote attacker could use this issue to cause
the server to stop responding, leading to a denial of service, or possibly
execute arbitrary code. (CVE-2014-0226)

Rainer Jung discovered that the mod_cgid module incorrectly handled certain
scripts. A remote attacker could use this issue to cause the server to stop
responding, leading to a denial of service. (CVE-2014-0231)";

  tag_affected = "apache2 on Ubuntu 14.04 LTS ,
  Ubuntu 12.04 LTS ,
  Ubuntu 10.04 LTS";

  tag_solution = "Please Install the Updated Packages.";


  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name: "USN", value: "2299-1");
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-2299-1/");
  script_summary("Check for the Version of apache2");
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

  if ((res = isdpkgvuln(pkg:"apache2-bin", ver:"2.4.7-1ubuntu4.1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU12.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"apache2.2-bin", ver:"2.2.22-1ubuntu1.7", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU10.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"apache2.2-bin", ver:"2.2.14-5ubuntu8.14", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
