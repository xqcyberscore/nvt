###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_3675_2.nasl 10222 2018-06-15 14:05:12Z cfischer $
#
# Ubuntu Update for gnupg2 USN-3675-2
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
  script_oid("1.3.6.1.4.1.25623.1.0.843562");
  script_version("$Revision: 10222 $");
  script_tag(name:"last_modification", value:"$Date: 2018-06-15 16:05:12 +0200 (Fri, 15 Jun 2018) $");
  script_tag(name:"creation_date", value:"2018-06-15 05:47:56 +0200 (Fri, 15 Jun 2018)");
  script_cve_id("CVE-2018-12020");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("Ubuntu Update for gnupg2 USN-3675-2");
  script_tag(name:"summary", value:"Check the version of gnupg2");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
on the target host.");
  script_tag(name:"insight", value:"USN-3675-1 fixed a vulnerability in GnuPG 2
for Ubuntu 18.04 LTS and Ubuntu 17.10. This update provides the corresponding
update for GnuPG 2 in Ubuntu 16.04 LTS and Ubuntu 14.04 LTS.

Original advisory details:

Marcus Brinkmann discovered that during decryption or verification,
GnuPG did not properly filter out terminal sequences when reporting the
original filename. An attacker could use this to specially craft a file
that would cause an application parsing GnuPG output to incorrectly
interpret the status of the cryptographic operation reported by GnuPG.");
  script_tag(name:"affected", value:"gnupg2 on Ubuntu 16.04 LTS ,
  Ubuntu 14.04 LTS");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"USN", value:"3675-2");
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-3675-2/");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04 LTS|16\.04 LTS)");
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

  if ((res = isdpkgvuln(pkg:"gnupg2", ver:"2.0.22-3ubuntu1.4", rls:"UBUNTU14.04 LTS", remove_arch:TRUE )) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU16.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"gnupg2", ver:"2.1.11-6ubuntu2.1", rls:"UBUNTU16.04 LTS", remove_arch:TRUE )) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
