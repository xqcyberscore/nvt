###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2018_6121f427e5_godot_fc27.nasl 11389 2018-09-14 14:20:05Z bshakeel $
#
# Fedora Update for godot FEDORA-2018-6121f427e5
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
  script_oid("1.3.6.1.4.1.25623.1.0.875056");
  script_version("$Revision: 11389 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-14 16:20:05 +0200 (Fri, 14 Sep 2018) $");
  script_tag(name:"creation_date", value:"2018-09-12 07:33:19 +0200 (Wed, 12 Sep 2018)");
  script_cve_id("CVE-2018-1000224");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for godot FEDORA-2018-6121f427e5");
  script_tag(name:"summary", value:"Check the version of godot");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");
  script_tag(name:"insight", value:"Godot is an advanced, feature-packed,
  multi-platform 2D and 3D game engine. It provides a huge set of common tools,
  so you can just focus on making your game without reinventing the wheel.

Godot is completely free and open source under the very permissive MIT
license. No strings attached, no royalties, nothing. Your game is yours,
down to the last line of engine code.
");
  script_tag(name:"affected", value:"godot on Fedora 27");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"FEDORA", value:"2018-6121f427e5");
  script_xref(name:"URL" , value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/ETDKHEQMHSXTRBNZ5WU67QSAPGKBXSSO");
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

  if ((res = isrpmvuln(pkg:"godot", rpm:"godot~3.0.6~1.fc27", rls:"FC27")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
