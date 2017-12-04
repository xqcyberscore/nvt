###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2017_4f9bb0861b_qt5-qtwebengine_fc27.nasl 7920 2017-11-28 07:49:35Z asteins $
#
# Fedora Update for qt5-qtwebengine FEDORA-2017-4f9bb0861b
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
  script_oid("1.3.6.1.4.1.25623.1.0.873800");
  script_version("$Revision: 7920 $");
  script_tag(name:"last_modification", value:"$Date: 2017-11-28 08:49:35 +0100 (Tue, 28 Nov 2017) $");
  script_tag(name:"creation_date", value:"2017-11-23 08:16:37 +0100 (Thu, 23 Nov 2017)");
  script_cve_id("CVE-2017-5092", "CVE-2017-5093", "CVE-2017-5095", "CVE-2017-5097", 
                "CVE-2017-5099", "CVE-2017-5102", "CVE-2017-5103", "CVE-2017-5107", 
                "CVE-2017-5112", "CVE-2017-5114", "CVE-2017-5117", "CVE-2017-5118");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for qt5-qtwebengine FEDORA-2017-4f9bb0861b");
  script_tag(name: "summary", value: "Check the version of qt5-qtwebengine");
  script_tag(name: "vuldetect", value: "Get the installed version with the help 
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "Qt5 - QtWebEngine components.
");
  script_tag(name: "affected", value: "qt5-qtwebengine on Fedora 27");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "FEDORA", value: "2017-4f9bb0861b");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/A7N3JOITXZYKROVZDADU3G3GPC7OPLLD");
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

if(release == "FC27")
{

  if ((res = isrpmvuln(pkg:"qt5-qtwebengine", rpm:"qt5-qtwebengine~5.9.2~2.fc27", rls:"FC27")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
