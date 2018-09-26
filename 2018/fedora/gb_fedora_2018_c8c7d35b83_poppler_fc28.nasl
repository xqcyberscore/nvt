###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2018_c8c7d35b83_poppler_fc28.nasl 11610 2018-09-26 02:42:29Z ckuersteiner $
#
# Fedora Update for poppler FEDORA-2018-c8c7d35b83
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
  script_oid("1.3.6.1.4.1.25623.1.0.874879");
  script_version("$Revision: 11610 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-26 04:42:29 +0200 (Wed, 26 Sep 2018) $");
  script_tag(name:"creation_date", value:"2018-08-02 06:04:19 +0200 (Thu, 02 Aug 2018)");
  script_cve_id("CVE-2018-13988", "CVE-2017-18267");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for poppler FEDORA-2018-c8c7d35b83");
  script_tag(name:"summary", value:"Check the version of poppler");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present 
on the target host.");
  script_tag(name:"insight", value:"poppler is a PDF rendering library.
");
  script_tag(name:"affected", value:"poppler on Fedora 28");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"FEDORA", value:"2018-c8c7d35b83");
  script_xref(name:"URL" , value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/UFJ4HNVK37HLZUQTQNVGRX53R37JIFL2");
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

  if ((res = isrpmvuln(pkg:"poppler", rpm:"poppler~0.62.0~3.fc28", rls:"FC28")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
