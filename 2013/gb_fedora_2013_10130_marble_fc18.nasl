###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for marble FEDORA-2013-10130
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

include("revisions-lib.inc");
tag_insight = "Marble is a Virtual Globe and World Atlas that you can use to learn more
  about Earth: You can pan and zoom around and you can look up places and
  roads. A mouse click on a place label will provide the respective Wikipedia
  article.

  Of course it's also possible to measure distances between locations or watch
  the current cloud cover. Marble offers different thematic maps: A classroom-
  style topographic map, a satellite view, street map, earth at night and
  temperature and precipitation maps. All maps include a custom map key, so it
  can also be used as an educational tool for use in class-rooms. For
  educational purposes you can also change date and time and watch how the
  starry sky and the twilight zone on the map change.

  In opposite to other virtual globes Marble also features multiple
  projections: Choose between a Flat Map (Plate carré), Mercator or the Globe.";


tag_affected = "marble on Fedora 18";
tag_solution = "Please Install the Updated Packages.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.865798");
  script_version("$Revision: 9353 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2013-06-13 10:03:26 +0530 (Thu, 13 Jun 2013)");
  script_cve_id("CVE-2013-2120");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Fedora Update for marble FEDORA-2013-10130");

  script_xref(name: "FEDORA", value: "2013-10130");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108627.html");
  script_tag(name: "summary" , value: "Check for the Version of marble");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms");
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");

res = "";
if(release == NULL){
  exit(0);
}

if(release == "FC18")
{

  if ((res = isrpmvuln(pkg:"marble", rpm:"marble~4.10.4~1.fc18", rls:"FC18")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
