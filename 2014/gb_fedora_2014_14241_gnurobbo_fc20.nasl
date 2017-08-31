###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for gnurobbo FEDORA-2014-14241
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.868451");
  script_version("$Revision: 6769 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-20 11:56:33 +0200 (Thu, 20 Jul 2017) $");
  script_tag(name:"creation_date", value:"2014-11-05 06:21:54 +0100 (Wed, 05 Nov 2014)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Fedora Update for gnurobbo FEDORA-2014-14241");
  script_tag(name: "summary", value: "Check the version of gnurobbo");
  script_tag(name: "vuldetect", value: "Get the installed version with the help of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "GNU Robbo is a free open source port of Janusz Pelc's Robbo
which was distributed by LK Avalon in 1989.

Features
   + Graphical skin support: Oily, Original and Tronic
   + Sound skin support: Default, Free and Oily
   + Support for user supplied music
   + 1113 levels across 28 packs converted from Robbo and Robbo Konstruktor
   + A mouse/stylus driven level designer
   + Support for Alex (a Robbo clone) objects
   + Support for Robbo Millennium objects
   + In-game help
   + Reconfigurable options and controls
   + Support for the mouse/stylus throughout the game
   + Support for keyboards, analogue and digital joysticks
   + Centering of game within any resolution  = 240x240
   + Simple build system to maximize porting potential
   + Support for locales

The game-play of the original is faithfully reproduced with a few modifications
   + Lives has been removed and suicide replaced with level restart
   + Scoring has been removed: goal is level advancement
   + Bears don't endlessly spin around themselves
   + Capsules don't spawn from question marks
   + Solid laser fire is not left live after the gun has been destroyed

Take a look into README.fedora about legal issues cause of missing content.
");
  script_tag(name: "affected", value: "gnurobbo on Fedora 20");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name: "FEDORA", value: "2014-14241");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/pipermail/package-announce/2014-November/142686.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
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

if(release == "FC20")
{

  if ((res = isrpmvuln(pkg:"gnurobbo", rpm:"gnurobbo~0.66~4.20141028svn412.fc20", rls:"FC20")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}