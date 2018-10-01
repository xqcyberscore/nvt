###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2018_1cb4c4a6d8_lcms2_fc28.nasl 11698 2018-09-29 03:57:28Z santu $
#
# Fedora Update for lcms2 FEDORA-2018-1cb4c4a6d8
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
  script_oid("1.3.6.1.4.1.25623.1.0.875106");
  script_version("$Revision: 11698 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-29 05:57:28 +0200 (Sat, 29 Sep 2018) $");
  script_tag(name:"creation_date", value:"2018-09-28 13:34:18 +0200 (Fri, 28 Sep 2018)");
  script_cve_id("CVE-2018-16435");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for lcms2 FEDORA-2018-1cb4c4a6d8");
  script_tag(name:"summary", value:"Check the version of lcms2");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");
  script_tag(name:"insight", value:"LittleCMS intends to be a small-footprint,
  speed optimized color management engine in open source form. LCMS2 is the current
  version of LCMS, and can be parallel installed with the original (deprecated) lcms.
");
  script_tag(name:"affected", value:"lcms2 on Fedora 28");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"FEDORA", value:"2018-1cb4c4a6d8");
  script_xref(name:"URL" , value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/ILGDBJPOHHN3S43OY6DWGBUZYKU5KJGP");
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

  if ((res = isrpmvuln(pkg:"lcms2", rpm:"lcms2~2.9~4.fc28", rls:"FC28")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
