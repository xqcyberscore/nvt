###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2018_520062dcb8_php-horde-horde_fc28.nasl 11820 2018-10-10 12:13:33Z santu $
#
# Fedora Update for php-horde-horde FEDORA-2018-520062dcb8
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
  script_oid("1.3.6.1.4.1.25623.1.0.875160");
  script_version("$Revision: 11820 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-10 14:13:33 +0200 (Wed, 10 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-10-08 08:26:30 +0200 (Mon, 08 Oct 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for php-horde-horde FEDORA-2018-520062dcb8");
  script_tag(name:"summary", value:"Check the version of php-horde-horde");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");
  script_tag(name:"insight", value:"The Horde Application Framework is a flexible,
  modular, general-purpose web application framework written in PHP. It provides
  an extensive array of components that are targeted at the common problems and
  tasks involved in developing modern web applications. It is the basis for a
  large number of production-level web applications, notably the Horde Groupware
  suites. For more information on Horde or the Horde Groupware suites.");
  script_tag(name:"affected", value:"php-horde-horde on Fedora 28");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"FEDORA", value:"2018-520062dcb8");
  script_xref(name:"URL" , value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/NKYQUHK5YTBDX4PMUPX7EEOVO52IFUPB");
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

  if ((res = isrpmvuln(pkg:"php-horde-horde", rpm:"php-horde-horde~5.2.20~1.fc28", rls:"FC28")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
