###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2018_28f30efaf6_cri-o_fc28.nasl 11281 2018-09-07 09:10:30Z cfischer $
#
# Fedora Update for cri-o FEDORA-2018-28f30efaf6
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
  script_oid("1.3.6.1.4.1.25623.1.0.874955");
  script_version("$Revision: 11281 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-07 11:10:30 +0200 (Fri, 07 Sep 2018) $");
  script_tag(name:"creation_date", value:"2018-08-16 06:09:32 +0200 (Thu, 16 Aug 2018)");
  script_cve_id("CVE-2018-10892");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for cri-o FEDORA-2018-28f30efaf6");
  script_tag(name:"summary", value:"Check the version of cri-o");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
on the target host.");
  script_tag(name:"insight", value:"Kubernetes Container Runtime Interface for
OCI-based containers
");
  script_tag(name:"affected", value:"cri-o on Fedora 28");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"FEDORA", value:"2018-28f30efaf6");
  script_xref(name:"URL" , value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/34NVOBDA5DKQHVEIZKLYOZPBYKPF26IX");
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

  if ((res = isrpmvuln(pkg:"cri-o", rpm:"cri-o~1.11.1~1.git1759204.fc28", rls:"FC28")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
