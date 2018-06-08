###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2018_812b5d5a71_chromium_fc27.nasl 10143 2018-06-08 13:43:47Z santu $
#
# Fedora Update for chromium FEDORA-2018-812b5d5a71
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
  script_oid("1.3.6.1.4.1.25623.1.0.874648");
  script_version("$Revision: 10143 $");
  script_tag(name:"last_modification", value:"$Date: 2018-06-08 15:43:47 +0200 (Fri, 08 Jun 2018) $");
  script_tag(name:"creation_date", value:"2018-06-06 10:24:11 +0200 (Wed, 06 Jun 2018)");
  script_cve_id("CVE-2018-6085", "CVE-2018-6086", "CVE-2018-6087", "CVE-2018-6088", 
                "CVE-2018-6089", "CVE-2018-6090", "CVE-2018-6091", "CVE-2018-6092", 
                "CVE-2018-6093", "CVE-2018-6094", "CVE-2018-6095", "CVE-2018-6096", 
                "CVE-2018-6097", "CVE-2018-6098", "CVE-2018-6099", "CVE-2018-6100", 
                "CVE-2018-6101", "CVE-2018-6102", "CVE-2018-6103", "CVE-2018-6104", 
                "CVE-2018-6105", "CVE-2018-6106", "CVE-2018-6107", "CVE-2018-6108", 
                "CVE-2018-6109", "CVE-2018-6110", "CVE-2018-6111", "CVE-2018-6112", 
                "CVE-2018-6113", "CVE-2018-6114", "CVE-2018-6116", "CVE-2018-6117", 
                "CVE-2018-6118", "CVE-2018-6121", "CVE-2018-6122", "CVE-2018-6120", 
                "CVE-2018-6115");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for chromium FEDORA-2018-812b5d5a71");
  script_tag(name:"summary", value:"Check the version of chromium");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present 
on the target host.");
  script_tag(name:"insight", value:"Chromium is an open-source web browser, 
powered by WebKit (Blink).
");
  script_tag(name:"affected", value:"chromium on Fedora 27");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"FEDORA", value:"2018-812b5d5a71");
  script_xref(name:"URL" , value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/N3R4UPGKKZ56KTGNOT2UBMDZTWJQWIM3");
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

  if ((res = isrpmvuln(pkg:"chromium", rpm:"chromium~66.0.3359.181~2.fc27", rls:"FC27")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
