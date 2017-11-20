###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_3476_1.nasl 7809 2017-11-17 09:43:26Z santu $
#
# Ubuntu Update for postgresql-common USN-3476-1
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.843362");
  script_version("$Revision: 7809 $");
  script_tag(name:"last_modification", value:"$Date: 2017-11-17 10:43:26 +0100 (Fri, 17 Nov 2017) $");
  script_tag(name:"creation_date", value:"2017-11-10 07:21:24 +0100 (Fri, 10 Nov 2017)");
  script_cve_id("CVE-2016-1255", "CVE-2017-8806");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("Ubuntu Update for postgresql-common USN-3476-1");
  script_tag(name: "summary", value: "Check the version of postgresql-common");
  script_tag(name: "vuldetect", value: "Get the installed version with the help
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "Dawid Golunski discovered that the
postgresql-common pg_ctlcluster script incorrectly handled symlinks. A local
attacker could possibly use this issue to escalate privileges. This issue only
affected Ubuntu 14.04 LTS and Ubuntu 16.04 LTS. (CVE-2016-1255)

It was discovered that the postgresql-common helper scripts incorrectly
handled symlinks. A local attacker could possibly use this issue to
escalate privileges. (CVE-2017-8806)");
  script_tag(name: "affected", value: "postgresql-common on Ubuntu 17.10 ,
  Ubuntu 17.04 ,
  Ubuntu 16.04 LTS ,
  Ubuntu 14.04 LTS");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "USN", value: "3476-1");
  script_xref(name: "URL" , value: "https://usn.ubuntu.com/usn/usn-3476-1/");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
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

  if ((res = isdpkgvuln(pkg:"postgresql-common", ver:"154ubuntu1.1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU17.10")
{

  if ((res = isdpkgvuln(pkg:"postgresql-common", ver:"184ubuntu1.1", rls:"UBUNTU17.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU17.04")
{

  if ((res = isdpkgvuln(pkg:"postgresql-common", ver:"179ubuntu0.1", rls:"UBUNTU17.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU16.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"postgresql-common", ver:"173ubuntu0.1", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
