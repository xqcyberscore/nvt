###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2018_d275e6ff0c_scummvm_fc27.nasl 9807 2018-05-11 17:48:42Z cfischer $
#
# Fedora Update for scummvm FEDORA-2018-d275e6ff0c
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
  script_oid("1.3.6.1.4.1.25623.1.0.874418");
  script_version("$Revision: 9807 $");
  script_tag(name:"last_modification", value:"$Date: 2018-05-11 19:48:42 +0200 (Fri, 11 May 2018) $");
  script_tag(name:"creation_date", value:"2018-05-06 05:45:20 +0200 (Sun, 06 May 2018)");
  script_cve_id("CVE-2017-17528");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for scummvm FEDORA-2018-d275e6ff0c");
  script_tag(name:"summary", value:"Check the version of scummvm");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present 
on the target host.");
  script_tag(name:"insight", value:"ScummVM is a program which allows you to 
run certain classic graphical point-and-click adventure games, provided you 
already have their data files.

ScummVM supports many adventure games, including LucasArts SCUMM games
(such as Monkey Island 1-3, Day of the Tentacle, Sam &amp  Max, ...),
many of Sierra&#39 s AGI and SCI games (such as King&#39 s Quest 1-6,
Space Quest 1-5, ...), Discworld 1 and 2, Simon the Sorcerer 1 and 2,
Beneath A Steel Sky, Lure of the Temptress, Broken Sword 1 and 2,
Flight of the Amazon Queen, Gobliiins 1-3, The Legend of Kyrandia 1-3,
many of Humongous Entertainment&#39 s children&#39 s SCUMM games (including
Freddi Fish and Putt Putt games) and many more.

The complete list can be found on ScummVM&#39 s compatibility page:
'http://scummvm.org/compatibility/2.0.0/'
");
  script_tag(name:"affected", value:"scummvm on Fedora 27");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"FEDORA", value:"2018-d275e6ff0c");
  script_xref(name:"URL" , value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/LGLZG2KLMJG7377TX4UCO27QKXZY2JWO");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");

res = "";
if(release == NULL){
  exit(0);
}

if(release == "FC27")
{

  if ((res = isrpmvuln(pkg:"scummvm", rpm:"scummvm~2.0.0~1.fc27", rls:"FC27")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
