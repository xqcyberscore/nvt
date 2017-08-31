###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for game-music-emu FEDORA-2016-fbf9f8b204
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.872168");
  script_version("$Revision: 6631 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-10 08:36:10 +0200 (Mon, 10 Jul 2017) $");
  script_tag(name:"creation_date", value:"2016-12-20 06:00:45 +0100 (Tue, 20 Dec 2016)");
  script_cve_id("CVE-2016-9957", "CVE-2016-9958", "CVE-2016-9959", "CVE-2016-9960",
                "CVE-2016-9961");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for game-music-emu FEDORA-2016-fbf9f8b204");
  script_tag(name: "summary", value: "Check the version of game-music-emu");

  script_tag(name: "vuldetect", value: "Get the installed version with the help
  of detect NVT and check if the version is vulnerable or not.");

  script_tag(name: "insight", value: "Game_Music_Emu is a collection of video
  game music file emulators that support the following formats and systems:

   * AY       ZX Spectrum/Amstrad CPC
   * GBS      Nintendo Game Boy
   * GYM      Sega Genesis/Mega Drive
   * HES      NEC TurboGrafx-16/PC Engine
   * KSS      MSX Home Computer/other Z80 systems (doesn&#39 t support FM sound)
   * NSF/NSFE Nintendo NES/Famicom (with VRC 6, Namco 106, and FME-7 sound)
   * SAP      Atari systems using POKEY sound chip
   * SPC      Super Nintendo/Super Famicom
   * VGM/VGZ  Sega Master System/Mark III, Sega Genesis/Mega Drive,BBC Micro");

  script_tag(name: "affected", value: "game-music-emu on Fedora 25");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "FEDORA", value: "2016-fbf9f8b204");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/GGHAQI5Q2XDSPGRRKPJJM3A73VWAFSFL");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
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

if(release == "FC25")
{

  if ((res = isrpmvuln(pkg:"game-music-emu", rpm:"game-music-emu~0.6.1~1.fc25", rls:"FC25")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
