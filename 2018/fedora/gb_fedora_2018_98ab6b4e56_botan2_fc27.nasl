###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2018_98ab6b4e56_botan2_fc27.nasl 10502 2018-07-13 13:19:46Z santu $
#
# Fedora Update for botan2 FEDORA-2018-98ab6b4e56
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
  script_oid("1.3.6.1.4.1.25623.1.0.874787");
  script_version("$Revision: 10502 $");
  script_tag(name:"last_modification", value:"$Date: 2018-07-13 15:19:46 +0200 (Fri, 13 Jul 2018) $");
  script_tag(name:"creation_date", value:"2018-07-12 06:10:21 +0200 (Thu, 12 Jul 2018)");
  script_cve_id("CVE-2018-12435", "CVE-2018-0495");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for botan2 FEDORA-2018-98ab6b4e56");
  script_tag(name:"summary", value:"Check the version of botan2");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present 
on the target host.");
  script_tag(name:"insight", value:"Botan is a BSD-licensed crypto library written 
in C++. It provides a wide variety of basic cryptographic algorithms, X.509 
certificates and CRLs, PKCS \#10 certificate requests, a filter/pipe message 
processing system, and a wide variety of other features, all written in portable
C++. The API reference, tutorial, and examples may help impart the flavor of the 
library. This is the current stable release branch 2.x of Botan.
");
  script_tag(name:"affected", value:"botan2 on Fedora 27");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"FEDORA", value:"2018-98ab6b4e56");
  script_xref(name:"URL" , value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/CFRHQ7MB53ZRVKO3BAF3WDWTS6A7CC7K");
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

  if ((res = isrpmvuln(pkg:"botan2", rpm:"botan2~2.7.0~1.fc27", rls:"FC27")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
