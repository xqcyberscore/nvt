###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2017_e3bf383b11_gnome-shell_fc25.nasl 7668 2017-11-06 13:16:04Z santu $
#
# Fedora Update for gnome-shell FEDORA-2017-e3bf383b11
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
  script_oid("1.3.6.1.4.1.25623.1.0.873564");
  script_version("$Revision: 7668 $");
  script_tag(name:"last_modification", value:"$Date: 2017-11-06 14:16:04 +0100 (Mon, 06 Nov 2017) $");
  script_tag(name:"creation_date", value:"2017-11-02 11:14:42 +0100 (Thu, 02 Nov 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for gnome-shell FEDORA-2017-e3bf383b11");
  script_tag(name: "summary", value: "Check the version of gnome-shell");
  script_tag(name: "vuldetect", value: "Get the installed version with the help 
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "GNOME Shell provides core user interface 
functions for the GNOME 3 desktop, like switching to windows and launching 
applications. GNOME Shell takes advantage of the capabilities of modern graphics 
hardware and introduces innovative user interface concepts to provide a visually 
attractive and easy to use experience.");
  script_tag(name: "affected", value: "gnome-shell on Fedora 25");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "FEDORA", value: "2017-e3bf383b11");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/CNQTIAZCV5B3KV5CNISIRMD5VPPPJSHS");
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

  if ((res = isrpmvuln(pkg:"gnome-shell", rpm:"gnome-shell~3.22.3~2.fc25", rls:"FC25")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
