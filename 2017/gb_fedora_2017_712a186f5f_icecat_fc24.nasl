###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for icecat FEDORA-2017-712a186f5f
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
  script_oid("1.3.6.1.4.1.25623.1.0.872553");
  script_version("$Revision: 6634 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-10 09:32:24 +0200 (Mon, 10 Jul 2017) $");
  script_tag(name:"creation_date", value:"2017-04-08 06:37:53 +0200 (Sat, 08 Apr 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for icecat FEDORA-2017-712a186f5f");
  script_tag(name: "summary", value: "Check the version of icecat");
  script_tag(name: "vuldetect", value: "Get the installed version with the help
  of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "GNUZilla Icecat is a fully-free fork of Mozilla Firefox ESR.
Extensions included to this version of IceCat:

 * LibreJS
   GNU LibreJS aims to address the JavaScript problem described in Richard
   Stallman&#39 s article The JavaScript Trap.

 * SpyBlock
   Blocks privacy trackers while in normal browsing mode, and all third party
   requests when in private browsing mode. Based on Adblock Plus.

 * AboutIceCat
   Adds a custom 'about:icecat' homepage with links to information about the
   free software and privacy features in IceCat, and check-boxes to enable
   and disable the ones more prone to break websites.

 * HTML5-video-everywhere
   Uses the native video player to play embedded videos from different sources

 * Fingerprinting countermeasures: Fingerprinting is a series of techniques
   allowing to uniquely identify a browser based on specific characterisics of
   that particular instance (like what fonts are available in that machine).
   Unlike cookies the user cannot opt-out of being tracked this way,
   so the browser has to avoid giving away that kind of hints.
");
  script_tag(name: "affected", value: "icecat on Fedora 24");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "FEDORA", value: "2017-712a186f5f");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/LY75DGGPW6FFUVT3B26HLNVH23DN24QG");
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

  if ((res = isrpmvuln(pkg:"icecat", rpm:"icecat~52.0.1~5.fc24", rls:"FC24")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
