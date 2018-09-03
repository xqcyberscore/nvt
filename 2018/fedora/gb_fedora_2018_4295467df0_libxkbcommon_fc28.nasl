###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2018_4295467df0_libxkbcommon_fc28.nasl 11173 2018-08-31 08:10:11Z santu $
#
# Fedora Update for libxkbcommon FEDORA-2018-4295467df0
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
  script_oid("1.3.6.1.4.1.25623.1.0.875013");
  script_version("$Revision: 11173 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-31 10:10:11 +0200 (Fri, 31 Aug 2018) $");
  script_tag(name:"creation_date", value:"2018-08-30 07:28:01 +0200 (Thu, 30 Aug 2018)");
  script_cve_id("CVE-2018-15853");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for libxkbcommon FEDORA-2018-4295467df0");
  script_tag(name:"summary", value:"Check the version of libxkbcommon");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
on the target host.");
  script_tag(name:"insight", value:"libxkbcommon is the X.Org library for
compiling XKB maps into formats usable by the X Server or other display servers.
");
  script_tag(name:"affected", value:"libxkbcommon on Fedora 28");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"FEDORA", value:"2018-4295467df0");
  script_xref(name:"URL" , value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/377JCLG64STYRNYZZ4B5QKGX2MAW6JUX");
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

  if ((res = isrpmvuln(pkg:"libxkbcommon", rpm:"libxkbcommon~0.8.2~1.fc28", rls:"FC28")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
