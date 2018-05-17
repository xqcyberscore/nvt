###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2018_389bc4e911_knot-resolver_fc28.nasl 9863 2018-05-16 12:29:42Z santu $
#
# Fedora Update for knot-resolver FEDORA-2018-389bc4e911
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
  script_oid("1.3.6.1.4.1.25623.1.0.874444");
  script_version("$Revision: 9863 $");
  script_tag(name:"last_modification", value:"$Date: 2018-05-16 14:29:42 +0200 (Wed, 16 May 2018) $");
  script_tag(name:"creation_date", value:"2018-05-16 05:50:46 +0200 (Wed, 16 May 2018)");
  script_cve_id("CVE-2018-1110");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for knot-resolver FEDORA-2018-389bc4e911");
  script_tag(name:"summary", value:"Check the version of knot-resolver");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present 
on the target host.");
  script_tag(name:"insight", value:"The Knot DNS Resolver is a caching full 
resolver implementation written in C and LuaJIT, including both a resolver 
library and a daemon. Modular architecture of the library keeps the core tiny 
and efficient, and provides a state-machine like API for extensions.

The package is pre-configured as local caching resolver.
To start using it, start a single kresd instance:
$ systemctl start kresd(a)1.service
");
  script_tag(name:"affected", value:"knot-resolver on Fedora 28");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"FEDORA", value:"2018-389bc4e911");
  script_xref(name:"URL" , value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/KYLXRIZMOFE4MPMIT77Z62ANOIIQX5K6");
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

  if ((res = isrpmvuln(pkg:"knot-resolver", rpm:"knot-resolver~2.3.0~1.fc28", rls:"FC28")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
