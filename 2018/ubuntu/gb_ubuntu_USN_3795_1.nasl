###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_3795_1.nasl 12126 2018-10-26 13:00:10Z cfischer $
#
# Ubuntu Update for libssh USN-3795-1
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.843662");
  script_version("$Revision: 12126 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 15:00:10 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-10-18 06:28:43 +0200 (Thu, 18 Oct 2018)");
  script_cve_id("CVE-2018-10933");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("Ubuntu Update for libssh USN-3795-1");
  script_tag(name:"summary", value:"Check the version of libssh");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Peter Winter-Smith discovered that libssh incorrectly handled
authentication when being used as a server. A remote attacker could use
this issue to bypass authentication without any credentials.");
  script_tag(name:"affected", value:"libssh on Ubuntu 18.04 LTS,
  Ubuntu 16.04 LTS,
  Ubuntu 14.04 LTS");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"USN", value:"3795-1");
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-3795-1/");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04 LTS|18\.04 LTS|16\.04 LTS)");
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

  if ((res = isdpkgvuln(pkg:"libssh-4", ver:"0.6.1-0ubuntu3.4", rls:"UBUNTU14.04 LTS", remove_arch:TRUE )) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU18.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libssh-4", ver:"0.8.0~20170825.94fa1e38-1ubuntu0.1", rls:"UBUNTU18.04 LTS", remove_arch:TRUE )) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU16.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libssh-4", ver:"0.6.3-4.3ubuntu0.1", rls:"UBUNTU16.04 LTS", remove_arch:TRUE )) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
