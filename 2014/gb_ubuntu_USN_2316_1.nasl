###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_2316_1.nasl 7957 2017-12-01 06:40:08Z santu $
#
# Ubuntu Update for subversion USN-2316-1
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
  script_oid("1.3.6.1.4.1.25623.1.0.841931");
  script_version("$Revision: 7957 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 07:40:08 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2014-08-15 05:56:40 +0200 (Fri, 15 Aug 2014)");
  script_cve_id("CVE-2014-0032", "CVE-2014-3522", "CVE-2014-3528");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_name("Ubuntu Update for subversion USN-2316-1");

  tag_insight = "Lieven Govaerts discovered that the Subversion mod_dav_svn
module incorrectly handled certain request methods when SVNListParentPath was
enabled. A remote attacker could use this issue to cause the server to
crash, resulting in a denial of service. This issue only affected Ubuntu
12.04 LTS. (CVE-2014-0032)

Ben Reser discovered that Subversion did not correctly validate SSL
certificates containing wildcards. A remote attacker could exploit this to
perform a man in the middle attack to view sensitive information or alter
encrypted communications. (CVE-2014-3522)

Bert Huijben discovered that Subversion did not properly handle cached
credentials. A malicious server could possibly use this issue to obtain
credentials cached for a different server. (CVE-2014-3528)";

  tag_affected = "subversion on Ubuntu 14.04 LTS ,
  Ubuntu 12.04 LTS";

  tag_solution = "Please Install the Updated Packages.";


  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name: "USN", value: "2316-1");
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-2316-1/");
  script_summary("Check for the Version of subversion");
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

  if ((res = isdpkgvuln(pkg:"libsvn1:i386", ver:"1.8.8-1ubuntu3.1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"subversion", ver:"1.8.8-1ubuntu3.1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU12.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libapache2-svn", ver:"1.6.17dfsg-3ubuntu3.4", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libsvn1", ver:"1.6.17dfsg-3ubuntu3.4", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"subversion", ver:"1.6.17dfsg-3ubuntu3.4", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
