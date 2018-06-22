###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2018_303a46d436_timidity++_fc27.nasl 10292 2018-06-22 03:53:38Z cfischer $
#
# Fedora Update for timidity++ FEDORA-2018-303a46d436
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
  script_oid("1.3.6.1.4.1.25623.1.0.874713");
  script_version("$Revision: 10292 $");
  script_tag(name:"last_modification", value:"$Date: 2018-06-22 05:53:38 +0200 (Fri, 22 Jun 2018) $");
  script_tag(name:"creation_date", value:"2018-06-21 06:19:15 +0200 (Thu, 21 Jun 2018)");
  script_cve_id("CVE-2017-11546", "CVE-2017-11547", "CVE-2017-11549");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for timidity++ FEDORA-2018-303a46d436");
  script_tag(name:"summary", value:"Check the version of timidity++");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"TiMidity++ is a MIDI format to wave table format converter and
player. Install timidity++ if you&#39 d like to play MIDI files and your
sound card does not natively support wave table format.
");
  script_tag(name:"affected", value:"timidity++ on Fedora 27");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"FEDORA", value:"2018-303a46d436");
  script_xref(name:"URL" , value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/II27TOOHZYPELZIEBMHOFKF37LMTAY3P");
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

  if ((res = isrpmvuln(pkg:"timidity++", rpm:"timidity++~2.14.0~16.fc27", rls:"FC27")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}