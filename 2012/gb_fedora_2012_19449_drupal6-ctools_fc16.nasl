###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for drupal6-ctools FEDORA-2012-19449
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

  Dependent -- a simple form widget to make form items appear
  and disappear based upon the selections in another item.

  Content -- plug-gable content types used as panes in Panels
  and other modules like Dashboard.

  Form wizard -- an API to make multiple-step forms much easier.

  CSS tools -- tools to cache and sanitize CSS easily to make user-input CSS safe.";

tag_affected = "drupal6-ctools on Fedora 16";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.fedoraproject.org/pipermail/package-announce/2012-December/094634.html");
  script_id(864939);
  script_version("$Revision: 8352 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-10 08:01:57 +0100 (Wed, 10 Jan 2018) $");
  script_tag(name:"creation_date", value:"2012-12-14 09:50:46 +0530 (Fri, 14 Dec 2012)");
  script_cve_id("CVE-2012-5559");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");
  script_xref(name: "FEDORA", value: "2012-19449");
  script_name("Fedora Update for drupal6-ctools FEDORA-2012-19449");

  script_tag(name: "summary" , value: "Check for the Version of drupal6-ctools");
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

if(release == "FC16")
{

  if ((res = isrpmvuln(pkg:"drupal6-ctools", rpm:"drupal6-ctools~1.10~1.fc16", rls:"FC16")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
