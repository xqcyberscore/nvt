###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2017_f58bbbbdb0_konversation_fc25.nasl 8018 2017-12-07 07:32:50Z teissa $
#
# Fedora Update for konversation FEDORA-2017-f58bbbbdb0
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
  script_oid("1.3.6.1.4.1.25623.1.0.873826");
  script_version("$Revision: 8018 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-07 08:32:50 +0100 (Thu, 07 Dec 2017) $");
  script_tag(name:"creation_date", value:"2017-12-04 18:48:35 +0530 (Mon, 04 Dec 2017)");
  script_cve_id("CVE-2017-15923");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for konversation FEDORA-2017-f58bbbbdb0");
  script_tag(name: "summary", value: "Check the version of konversation");
  script_tag(name: "vuldetect", value: "Get the installed version with the help 
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "A simple and easy to use IRC client with 
support for strikeout  multi-channel joins  away / unaway messages ignore list 
functionality  support for foreign language characters  auto-connect to server  
optional timestamps to chat windows  configurable background colors and much 
more.");
  script_tag(name: "affected", value: "konversation on Fedora 25");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "FEDORA", value: "2017-f58bbbbdb0");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/RW5VQESQ67GCQ2DMWQI2E5Z3LTHE7JMU");
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

  if ((res = isrpmvuln(pkg:"konversation", rpm:"konversation~1.7.4~1.fc25", rls:"FC25")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
