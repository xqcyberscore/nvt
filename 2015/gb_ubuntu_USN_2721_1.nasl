###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for subversion USN-2721-1
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842420");
  script_version("$Revision: 7956 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 06:53:44 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2015-08-21 07:50:15 +0200 (Fri, 21 Aug 2015)");
  script_cve_id("CVE-2014-3580", "CVE-2014-8108", "CVE-2015-0202", "CVE-2015-0248",
                "CVE-2015-0251", "CVE-2015-3184", "CVE-2015-3187");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("Ubuntu Update for subversion USN-2721-1");
  script_tag(name: "summary", value: "Check the version of subversion");
  script_tag(name: "vuldetect", value: "Get the installed version with the help
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "It was discovered that the Subversion
mod_dav_svn module incorrectly handled REPORT requests for a resource that does
not exist. A remote attacker could use this issue to cause the server to crash,
resulting in a denial of service. This issue only affected Ubuntu 12.04 LTS
and Ubuntu 14.04 LTS. (CVE-2014-3580)

It was discovered that the Subversion mod_dav_svn module incorrectly
handled requests requiring a lookup for a virtual transaction name that
does not exist. A remote attacker could use this issue to cause the server
to crash, resulting in a denial of service. This issue only affected Ubuntu
14.04 LTS. (CVE-2014-8108)

Evgeny Kotkov discovered that the Subversion mod_dav_svn module incorrectly
handled large numbers of REPORT requests. A remote attacker could use this
issue to cause the server to crash, resulting in a denial of service. This
issue only affected Ubuntu 14.04 LTS and Ubuntu 15.04. (CVE-2015-0202)

Evgeny Kotkov discovered that the Subversion mod_dav_svn and svnserve
modules incorrectly certain crafted parameter combinations. A remote
attacker could use this issue to cause the server to crash, resulting in a
denial of service. (CVE-2015-0248)

Ivan Zhakov discovered that the Subversion mod_dav_svn module incorrectly
handled crafted v1 HTTP protocol request sequences. A remote attacker could
use this issue to spoof the svn:author property. (CVE-2015-0251)

C. Michael Pilato discovered that the Subversion mod_dav_svn module
incorrectly restricted anonymous access. A remote attacker could use this
issue to read hidden files via the path name. This issue only affected
Ubuntu 14.04 LTS and Ubuntu 15.04. (CVE-2015-3184)

C. Michael Pilato discovered that Subversion incorrectly handled path-based
authorization. A remote attacker could use this issue to obtain sensitive
path information. (CVE-2015-3187)");
  script_tag(name: "affected", value: "subversion on Ubuntu 14.04 LTS ,
  Ubuntu 12.04 LTS");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");
  script_xref(name: "USN", value: "2721-1");
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-2721-1/");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = get_kb_item("ssh/login/release");

res = "";
if(release == NULL){
  exit(0);
}

if(release == "UBUNTU14.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libapache2-svn", ver:"1.8.8-1ubuntu3.2", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libsvn1:amd64", ver:"1.8.8-1ubuntu3.2", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }
  if ((res = isdpkgvuln(pkg:"libsvn1:i386", ver:"1.8.8-1ubuntu3.2", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"subversion", ver:"1.8.8-1ubuntu3.2", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU12.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libapache2-svn", ver:"1.6.17dfsg-3ubuntu3.5", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libsvn1", ver:"1.6.17dfsg-3ubuntu3.5", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"subversion", ver:"1.6.17dfsg-3ubuntu3.5", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
