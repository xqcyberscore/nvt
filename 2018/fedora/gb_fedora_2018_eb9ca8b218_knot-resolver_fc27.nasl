###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2018_eb9ca8b218_knot-resolver_fc27.nasl 11042 2018-08-18 06:42:47Z santu $
#
# Fedora Update for knot-resolver FEDORA-2018-eb9ca8b218
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
  script_oid("1.3.6.1.4.1.25623.1.0.874930");
  script_version("$Revision: 11042 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-18 08:42:47 +0200 (Sat, 18 Aug 2018) $");
  script_tag(name:"creation_date", value:"2018-08-15 06:35:34 +0200 (Wed, 15 Aug 2018)");
  script_cve_id("CVE-2018-10920", "CVE-2018-1110", "CVE-2018-1000002");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for knot-resolver FEDORA-2018-eb9ca8b218");
  script_tag(name:"summary", value:"Check the version of knot-resolver");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
on the target host.");
  script_tag(name:"insight", value:"The Knot DNS Resolver is a caching full
resolver implementation written in C and LuaJIT, including both a resolver
library and a daemon. Modular architecture of the library keeps the core tiny
and efficient, and provides a state-machine like API for extensions.

The package is pre-configured as local caching resolver. To start using it,
start a single kresd instance: $ systemctl start kresd(a)1.service
");
  script_tag(name:"affected", value:"knot-resolver on Fedora 27");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"FEDORA", value:"2018-eb9ca8b218");
  script_xref(name:"URL" , value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/ESZGJSHNQHB6SHEWXTJ6GK7VMU2SLLQE");
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

  if ((res = isrpmvuln(pkg:"knot-resolver", rpm:"knot-resolver~2.4.1~1.fc27", rls:"FC27")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
