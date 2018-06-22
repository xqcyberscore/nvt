###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_3687_1.nasl 10284 2018-06-21 11:19:30Z cfischer $
#
# Ubuntu Update for webkit2gtk USN-3687-1
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
  script_oid("1.3.6.1.4.1.25623.1.0.843564");
  script_version("$Revision: 10284 $");
  script_tag(name:"last_modification", value:"$Date: 2018-06-21 13:19:30 +0200 (Thu, 21 Jun 2018) $");
  script_tag(name:"creation_date", value:"2018-06-19 06:01:01 +0200 (Tue, 19 Jun 2018)");
  script_cve_id("CVE-2018-12293", "CVE-2018-4190", "CVE-2018-4199", "CVE-2018-4218", "CVE-2018-4222", "CVE-2018-4232", "CVE-2018-4233");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("Ubuntu Update for webkit2gtk USN-3687-1");
  script_tag(name:"summary", value:"Check the version of webkit2gtk");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"A large number of security issues were discovered in the WebKitGTK+ Web and
JavaScript engines. If a user were tricked into viewing a malicious
website, a remote attacker could exploit a variety of issues related to web
browser security, including cross-site scripting attacks, denial of service
attacks, and arbitrary code execution.");
  script_tag(name:"affected", value:"webkit2gtk on Ubuntu 18.04 LTS ,
  Ubuntu 17.10 ,
  Ubuntu 16.04 LTS");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"USN", value:"3687-1");
  script_xref(name:"URL" , value:"https://lists.ubuntu.com/archives/ubuntu-security-announce/2018-June/004452.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(17\.10|18\.04 LTS|16\.04 LTS)");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = get_kb_item("ssh/login/release");

res = "";
if(release == NULL){
  exit(0);
}

if(release == "UBUNTU17.10")
{

  if ((res = isdpkgvuln(pkg:"libjavascriptcoregtk-4.0-18", ver:"2.20.3-0ubuntu0.17.10.1", rls:"UBUNTU17.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libwebkit2gtk-4.0-37", ver:"2.20.3-0ubuntu0.17.10.1", rls:"UBUNTU17.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU18.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libjavascriptcoregtk-4.0-18", ver:"2.20.3-0ubuntu0.18.04.1", rls:"UBUNTU18.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libwebkit2gtk-4.0-37", ver:"2.20.3-0ubuntu0.18.04.1", rls:"UBUNTU18.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU16.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libjavascriptcoregtk-4.0-18", ver:"2.20.3-0ubuntu0.16.04.1", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libwebkit2gtk-4.0-37", ver:"2.20.3-0ubuntu0.16.04.1", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}