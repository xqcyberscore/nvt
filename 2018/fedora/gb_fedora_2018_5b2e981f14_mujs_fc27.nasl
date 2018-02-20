###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2018_5b2e981f14_mujs_fc27.nasl 8858 2018-02-19 06:07:22Z cfischer $
#
# Fedora Update for mujs FEDORA-2018-5b2e981f14
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
  script_oid("1.3.6.1.4.1.25623.1.0.874121");
  script_version("$Revision: 8858 $");
  script_tag(name:"last_modification", value:"$Date: 2018-02-19 07:07:22 +0100 (Mon, 19 Feb 2018) $");
  script_tag(name:"creation_date", value:"2018-02-15 08:50:18 +0100 (Thu, 15 Feb 2018)");
  script_cve_id("CVE-2018-5759", "CVE-2018-6191");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for mujs FEDORA-2018-5b2e981f14");
  script_tag(name: "summary", value: "Check the version of mujs");
  script_tag(name: "vuldetect", value: "Get the installed version with the help 
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "MuJS is a lightweight Javascript interpreter 
designed for embedding in other software to extend them with scripting capabilities.
");
  script_tag(name: "affected", value: "mujs on Fedora 27");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "FEDORA", value: "2018-5b2e981f14");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/FLDFOXVGLVSJOYM5J3HZKGJ24UFJKZZH");
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

  if ((res = isrpmvuln(pkg:"mujs-0", rpm:"mujs-0~11.20180129git25821e6.fc27", rls:"FC27")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
