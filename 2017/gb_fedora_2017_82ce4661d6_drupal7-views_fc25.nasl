###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for drupal7-views FEDORA-2017-82ce4661d6
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
  script_oid("1.3.6.1.4.1.25623.1.0.872459");
  script_version("$Revision: 6634 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-10 09:32:24 +0200 (Mon, 10 Jul 2017) $");
  script_tag(name:"creation_date", value:"2017-03-09 17:44:17 +0100 (Thu, 09 Mar 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for drupal7-views FEDORA-2017-82ce4661d6");
  script_tag(name: "summary", value: "Check the version of drupal7-views");
  script_tag(name: "vuldetect", value: "Get the installed version with the help
  of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "You need Views if:
* You like the default front page view, but you find you want to sort it
  differently.
* You like the default taxonomy/term view, but you find you want to sort it
  differently  for example, alphabetically.
* You use /tracker, but you want to restrict it to posts of a certain type.
* You like the idea of the &#39 article&#39  module, but it doesn&#39 t display articles
  the way you like.
* You want a way to display a block with the 5 most recent posts of some
  particular type.
* You want to provide &#39 unread forum posts&#39 .
* You want a monthly archive similar to the typical Movable Type/Wordpress
  archives that displays a link to the in the form of 'Month, YYYY (X)' where
  X is the number of posts that month, and displays them in a block. The links
  lead to a simple list of posts for that month.

Views can do a lot more than that, but those are some of the obvious uses of
Views.

This package provides the following Drupal 7 modules:
* views
* views_ui
");
  script_tag(name: "affected", value: "drupal7-views on Fedora 25");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "FEDORA", value: "2017-82ce4661d6");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/RS5WHRIGSUIGCJUBRG2BBWPWWRCL3FAA");
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

  if ((res = isrpmvuln(pkg:"drupal7-views", rpm:"drupal7-views~3.15~1.fc25", rls:"FC25")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
