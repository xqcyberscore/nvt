###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for drupal6-ctools FEDORA-2015-14331
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.869926");
  script_version("$Revision: 6630 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-10 08:34:32 +0200 (Mon, 10 Jul 2017) $");
  script_tag(name:"creation_date", value:"2015-09-07 06:07:30 +0200 (Mon, 07 Sep 2015)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for drupal6-ctools FEDORA-2015-14331");
  script_tag(name: "summary", value: "Check the version of drupal6-ctools");
  script_tag(name: "vuldetect", value: "Get the installed version with the help
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "This suite is primarily a set of APIs and
tools to improve the developer experience. It also contains a module called the
Page Manager whose job is to manage pages. In particular it manages panel pages,
but as it grows it will be able to manage far more than just Panels.

For the moment, it includes the following tools:
* Plugins -- tools to make it easy for modules to let other modules implement
      plugins from .inc files.
* Exportables -- tools to make it easier for modules to have objects that live
      in database or live in code, such as 'default views'.
* AJAX responder -- tools to make it easier for the server to handle AJAX
  requests and tell the client what to do with them.
* Form tools -- tools to make it easier for forms to deal with AJAX.
* Object caching -- tool to make it easier to edit an object across multiple
      page requests and cache the editing work.
* Contexts -- the notion of wrapping objects in a unified wrapper and providing
      an API to create and accept these contexts as input.
* Modal dialog -- tool to make it simple to put a form in a modal dialog.
* Dependent -- a simple form widget to make form items appear and disappear
      based upon the selections in another item.
* Content -- pluggable content types used as panes in Panels and other modules
      like Dashboard.
* Form wizard -- an API to make multi-step forms much easier.
* CSS tools -- tools to cache and sanitize CSS easily to make user-input CSS
      safe.

This package provides the following Drupal modules:
* bulk_export
* ctools
* ctools_access_ruleset
* ctools_ajax_sample
* ctools_custom_content
* ctools_plugin_example
* page_manager
* stylizer
* views_content
");
  script_tag(name: "affected", value: "drupal6-ctools on Fedora 22");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");
  script_xref(name: "FEDORA", value: "2015-14331");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/pipermail/package-announce/2015-September/165695.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
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

if(release == "FC22")
{

  if ((res = isrpmvuln(pkg:"drupal6-ctools", rpm:"drupal6-ctools~1.14~1.fc22", rls:"FC22")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
