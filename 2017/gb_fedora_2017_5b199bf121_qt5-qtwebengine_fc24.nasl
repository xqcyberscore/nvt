###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2017_5b199bf121_qt5-qtwebengine_fc24.nasl 7798 2017-11-17 05:43:16Z teissa $
#
# Fedora Update for qt5-qtwebengine FEDORA-2017-5b199bf121
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.873216");
  script_version("$Revision: 7798 $");
  script_tag(name:"last_modification", value:"$Date: 2017-11-17 06:43:16 +0100 (Fri, 17 Nov 2017) $");
  script_tag(name:"creation_date", value:"2017-08-07 07:40:09 +0200 (Mon, 07 Aug 2017)");
  script_cve_id("CVE-2017-5052", "CVE-2017-5054");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for qt5-qtwebengine FEDORA-2017-5b199bf121");
  script_tag(name: "summary", value: "Check the version of qt5-qtwebengine");
  script_tag(name: "vuldetect", value: "Get the installed version with the help 
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "Qt5 - QtWebEngine components.
");
  script_tag(name: "affected", value: "qt5-qtwebengine on Fedora 24");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "FEDORA", value: "2017-5b199bf121");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/2A7GIS3VPXTOYJRRX7HVYDVMTY3ACNEY");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
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

if(release == "FC24")
{

  if ((res = isrpmvuln(pkg:"qt5-qtwebengine", rpm:"qt5-qtwebengine~5.6.3~0.2.20170712gitee719ad313e564.fc24", rls:"FC24")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
