###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2018_f4f75985b8_soundtouch_fc28.nasl 11972 2018-10-19 05:34:20Z cfischer $
#
# Fedora Update for soundtouch FEDORA-2018-f4f75985b8
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
  script_oid("1.3.6.1.4.1.25623.1.0.874978");
  script_version("$Revision: 11972 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 07:34:20 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-08-21 06:57:14 +0200 (Tue, 21 Aug 2018)");
  script_cve_id("CVE-2018-14044", "CVE-2018-14045", "CVE-2018-1000223", "CVE-2017-9258",
                "CVE-2017-9259", "CVE-2017-9260");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for soundtouch FEDORA-2018-f4f75985b8");
  script_tag(name:"summary", value:"Check the version of soundtouch");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
on the target host.");
  script_tag(name:"insight", value:"SoundTouch is a LGPL-licensed open-source
audio processing library for changing the Tempo, Pitch and Playback Rates of
audio streams or files. The SoundTouch library is suited for application developers
writing sound processing tools that require tempo/pitch control functionality,
or just for playing around with the sound effects.

The SoundTouch library source kit includes an example utility SoundStretch
which allows processing .wav audio files from a command-line interface.
");
  script_tag(name:"affected", value:"soundtouch on Fedora 28");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"FEDORA", value:"2018-f4f75985b8");
  script_xref(name:"URL" , value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/PA4WRBGUOIUFQNNFWZ5NRQ6K7S63JU6G");
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

if(release == "FC28")
{

  if ((res = isrpmvuln(pkg:"soundtouch", rpm:"soundtouch~2.0.0~6.fc28", rls:"FC28")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
