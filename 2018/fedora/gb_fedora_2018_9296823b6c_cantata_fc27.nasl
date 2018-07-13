###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2018_9296823b6c_cantata_fc27.nasl 10480 2018-07-11 10:23:47Z santu $
#
# Fedora Update for cantata FEDORA-2018-9296823b6c
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
  script_oid("1.3.6.1.4.1.25623.1.0.874778");
  script_version("$Revision: 10480 $");
  script_tag(name:"last_modification", value:"$Date: 2018-07-11 12:23:47 +0200 (Wed, 11 Jul 2018) $");
  script_tag(name:"creation_date", value:"2018-07-07 06:06:11 +0200 (Sat, 07 Jul 2018)");
  script_cve_id("CVE-2018-12562", "CVE-2018-12561", "CVE-2018-12560", "CVE-2018-12559");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for cantata FEDORA-2018-9296823b6c");
  script_tag(name:"summary", value:"Check the version of cantata");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present 
on the target host.");
  script_tag(name:"insight", value:"Cantata is a graphical client for the music player 
daemon (MPD).
Features:
* Multiple MPD collections.
* Highly customisable layout.
* Songs grouped by album in play queue.
* Context view to show artist, album, and song information of current track.
* Simple tag editor.
* File organizer - use tags to organize files and folders.
* Ability to calculate ReplyGain tags.
* Dynamic playlists.
* Online services  Jamendo, Magnatune, SoundCloud, and Podcasts.
* Radio stream support - with the ability to search for streams via TuneIn
and ShoutCast.
* USB-Mass-Storage and MTP device support.
* Audio CD ripping and playback.
* Playback of non-MPD songs, via simple in-built HTTP server.
* MPRISv2 DBUS interface.
* Support for KDE global shortcuts (KDE builds), GNOME media keys, and generic
media keys (via Qxt support)
* Ubuntu/ambiance theme integration.
");
  script_tag(name:"affected", value:"cantata on Fedora 27");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"FEDORA", value:"2018-9296823b6c");
  script_xref(name:"URL" , value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/GKSK32KTXLRRNHWZF5XFWRMJ24A33OSM");
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

  if ((res = isrpmvuln(pkg:"cantata", rpm:"cantata~2.3.1~1.fc27", rls:"FC27")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
