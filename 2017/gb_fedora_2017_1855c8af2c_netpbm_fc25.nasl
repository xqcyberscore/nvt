###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for netpbm FEDORA-2017-1855c8af2c
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
  script_oid("1.3.6.1.4.1.25623.1.0.872360");
  script_version("$Revision: 11561 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-24 08:20:05 +0200 (Mon, 24 Sep 2018) $");
  script_tag(name:"creation_date", value:"2017-02-20 11:39:00 +0100 (Mon, 20 Feb 2017)");
  script_cve_id("CVE-2017-2586", "CVE-2017-2587", "CVE-2017-5849");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for netpbm FEDORA-2017-1855c8af2c");
  script_tag(name: "summary", value: "Check the version of netpbm");
  script_tag(name: "vuldetect", value: "Get the installed version with the help of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "The netpbm package contains a library of functions which support
programs for handling various graphics file formats, including .pbm
(portable bitmaps), .pgm (portable graymaps), .pnm (portable anymaps),
.ppm (portable pixmaps) and others.
");
  script_tag(name: "affected", value: "netpbm on Fedora 25");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "FEDORA", value: "2017-1855c8af2c");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/LDK3BDMKIQL2NQ3SJZXPBEN2LSOUSSEE");
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

if(release == "FC25")
{

  if ((res = isrpmvuln(pkg:"netpbm", rpm:"netpbm~10.77.00~3.fc25", rls:"FC25")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}