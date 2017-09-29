###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2017_aa7a8871b7_mingw-LibRaw_fc25.nasl 7318 2017-09-29 05:31:27Z asteins $
#
# Fedora Update for mingw-LibRaw FEDORA-2017-aa7a8871b7
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
  script_oid("1.3.6.1.4.1.25623.1.0.873456");
  script_version("$Revision: 7318 $");
  script_tag(name:"last_modification", value:"$Date: 2017-09-29 07:31:27 +0200 (Fri, 29 Sep 2017) $");
  script_tag(name:"creation_date", value:"2017-09-28 09:16:07 +0200 (Thu, 28 Sep 2017)");
  script_cve_id("CVE-2017-14348", "CVE-2017-13735");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for mingw-LibRaw FEDORA-2017-aa7a8871b7");
  script_tag(name: "summary", value: "Check the version of mingw-LibRaw");
  script_tag(name: "vuldetect", value: "Get the installed version with the help 
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "MinGW Windows LibRaw library.
");
  script_tag(name: "affected", value: "mingw-LibRaw on Fedora 25");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "FEDORA", value: "2017-aa7a8871b7");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/OPKCTEX7MK4ILYKIBQBK3VBM5U5CRJKK");
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

  if ((res = isrpmvuln(pkg:"mingw32-LibRaw", rpm:"mingw32-LibRaw~0.17.2~3.fc25", rls:"FC25")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"mingw64-LibRaw", rpm:"mingw64-LibRaw~0.17.2~3.fc25", rls:"FC25")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
