###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for drupal7-ctools FEDORA-2012-5094
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_insight = "This suite is primarily a set of APIs and tools
  to improve the developer experience.
  It also contains a module called the Page Manager whose job is to manage pages.
  In particular it manages panel pages,
  but as it grows it will be able to manage far more than just Panels.

  For the moment, it includes the following tools:

  Plug-ins -- tools to make it easy for modules
  to let other modules implement plug-ins from .inc files.

  Ex-portables -- tools to make it easier for modules to have objects
  that live in database or live in code, such as 'default views'.

  AJAX responder -- tools to make it easier for the server to handle AJAX requests
  and tell the client what to do with them.

  Form tools -- tools to make it easier for forms to deal with AJAX.

  Object caching -- tool to make it easier to edit an object
  across multiple page requests and cache the editing work.

  Contexts -- the notion of wrapping objects in a unified wrapper
  and providing an API to create and accept these contexts as input.

  Modal dialog -- tool to make it simple to put a form in a modal dialog.

  Dependent -- a simple form widget to make form items appear
  and disappear based upon the selections in another item.

  Content -- plug-gable content types used as panes in Panels
  and other modules like Dashboard.

  Form wizard -- an API to make multiple-step forms much easier.

  CSS tools -- tools to cache and sanitize CSS easily to make user-input CSS safe.";

tag_affected = "drupal7-ctools on Fedora 15";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.fedoraproject.org/pipermail/package-announce/2012-April/077016.html");
  script_id(864143);
  script_version("$Revision: 8273 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-03 07:29:19 +0100 (Wed, 03 Jan 2018) $");
  script_tag(name:"creation_date", value:"2012-04-11 10:48:19 +0530 (Wed, 11 Apr 2012)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_xref(name: "FEDORA", value: "2012-5094");
  script_name("Fedora Update for drupal7-ctools FEDORA-2012-5094");

  script_tag(name: "summary" , value: "Check for the Version of drupal7-ctools");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
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

if(release == "FC15")
{

  if ((res = isrpmvuln(pkg:"drupal7-ctools", rpm:"drupal7-ctools~1.0~1.fc15", rls:"FC15")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
