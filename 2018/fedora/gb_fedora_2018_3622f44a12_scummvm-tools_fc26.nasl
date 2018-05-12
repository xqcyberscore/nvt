###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2018_3622f44a12_scummvm-tools_fc26.nasl 9807 2018-05-11 17:48:42Z cfischer $
#
# Fedora Update for scummvm-tools FEDORA-2018-3622f44a12
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
  script_oid("1.3.6.1.4.1.25623.1.0.874419");
  script_version("$Revision: 9807 $");
  script_tag(name:"last_modification", value:"$Date: 2018-05-11 19:48:42 +0200 (Fri, 11 May 2018) $");
  script_tag(name:"creation_date", value:"2018-05-06 05:45:23 +0200 (Sun, 06 May 2018)");
  script_cve_id("CVE-2017-17528");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for scummvm-tools FEDORA-2018-3622f44a12");
  script_tag(name:"summary", value:"Check the version of scummvm-tools");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present 
on the target host.");
  script_tag(name:"insight", value:"This is a collection of various tools that 
may be useful to use in conjunction with ScummVM.
Please note that although a tool may support a feature, certain ScummVM
versions may not. ScummVM 0.6.x does not support FLAC audio, for example.

Many games package together all their game data in a few big archive files.
The following tools can be used to extract these archives, and in some cases
are needed to make certain game versions usable with ScummVM.

The following tools can also be used to analyze the game scripts
(controlling the behavior of certain scenes and actors in a game).
These tools are most useful to developers.
");
  script_tag(name:"affected", value:"scummvm-tools on Fedora 26");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"FEDORA", value:"2018-3622f44a12");
  script_xref(name:"URL" , value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/FESRFMTYBCRSK2CYB36QEOH2EJEBANMG");
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

if(release == "FC26")
{

  if ((res = isrpmvuln(pkg:"scummvm-tools", rpm:"scummvm-tools~2.0.0~1.fc26", rls:"FC26")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
