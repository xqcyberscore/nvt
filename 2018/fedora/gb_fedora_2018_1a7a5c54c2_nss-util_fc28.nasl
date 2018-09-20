###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2018_1a7a5c54c2_nss-util_fc28.nasl 11471 2018-09-19 11:17:08Z santu $
#
# Fedora Update for nss-util FEDORA-2018-1a7a5c54c2
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
  script_oid("1.3.6.1.4.1.25623.1.0.875068");
  script_version("$Revision: 11471 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-19 13:17:08 +0200 (Wed, 19 Sep 2018) $");
  script_tag(name:"creation_date", value:"2018-09-15 07:42:06 +0200 (Sat, 15 Sep 2018)");
  script_cve_id("CVE-2018-12384");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for nss-util FEDORA-2018-1a7a5c54c2");
  script_tag(name:"summary", value:"Check the version of nss-util");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");
  script_tag(name:"insight", value:"Utilities for Network Security Services and
  the Softoken module
");
  script_tag(name:"affected", value:"nss-util on Fedora 28");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"FEDORA", value:"2018-1a7a5c54c2");
  script_xref(name:"URL" , value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/RFD2PFV43FQSZMWUM6LAJW2JHUYGTZ6A");
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

  if ((res = isrpmvuln(pkg:"nss-util", rpm:"nss-util~3.39.0~1.0.fc28", rls:"FC28")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
