###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2018_9c0b765d2d_wesnoth_fc27.nasl 11610 2018-09-26 02:42:29Z ckuersteiner $
#
# Fedora Update for wesnoth FEDORA-2018-9c0b765d2d
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
  script_oid("1.3.6.1.4.1.25623.1.0.874870");
  script_version("$Revision: 11610 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-26 04:42:29 +0200 (Wed, 26 Sep 2018) $");
  script_tag(name:"creation_date", value:"2018-08-02 06:01:19 +0200 (Thu, 02 Aug 2018)");
  script_cve_id("CVE-2018-1999023");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for wesnoth FEDORA-2018-9c0b765d2d");
  script_tag(name:"summary", value:"Check the version of wesnoth");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present 
on the target host.");
  script_tag(name:"insight", value:"The Battle for Wesnoth is a turn-based 
strategy game with a fantasy theme.

Build up a great army, gradually turning raw recruits into hardened
veterans. In later games, recall your toughest warriors and form a deadly
host against whom none can stand. Choose units from a large pool of
specialists, and hand-pick a force with the right strengths to fight well
on different terrains against all manner of opposition.

Fight to regain the throne of Wesnoth, of which you are the legitimate
heir, or use your dread power over the Undead to dominate the land of
mortals, or lead your glorious Orcish tribe to victory against the humans
who dared despoil your lands. Wesnoth has many different sagas waiting to
be played out. You can create your own custom units, and write your own
scenarios--or even full-blown campaigns. You can also challenge your
friends--or strangers--and fight multi-player epic fantasy battles.
");
  script_tag(name:"affected", value:"wesnoth on Fedora 27");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"FEDORA", value:"2018-9c0b765d2d");
  script_xref(name:"URL" , value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/GWNGLIXCOWAWDPXBPNMRVJ7XRT764JBH");
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

  if ((res = isrpmvuln(pkg:"wesnoth", rpm:"wesnoth~1.14.4~1.fc27", rls:"FC27")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
