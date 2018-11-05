###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for nodejs-tough-cookie FEDORA-2016-286a8ec5b0
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.809957");
  script_version("$Revision: 12208 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-05 05:24:03 +0100 (Mon, 05 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-11-14 18:00:18 +0530 (Mon, 14 Nov 2016)");
  script_cve_id("CVE-2016-1000232");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for nodejs-tough-cookie FEDORA-2016-286a8ec5b0");
  script_tag(name: "summary", value: "Check the version of nodejs-tough-cookie");

  script_tag(name: "vuldetect", value: "Get the installed version with the help
  of detect NVT and check if the version is vulnerable or not.");

  script_tag(name: "insight", value: "RFC6265 Cookies and Cookie Jar for
  Node.js.");

  script_tag(name: "affected", value: "nodejs-tough-cookie on Fedora 23");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "FEDORA", value: "2016-286a8ec5b0");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/TZB7Z3WJE2G5XGENZ54N3X6EW6MCMOZK");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
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

if(release == "FC23")
{

  if ((res = isrpmvuln(pkg:"nodejs-tough-cookie", rpm:"nodejs-tough-cookie~2.3.1~1.fc23", rls:"FC23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
