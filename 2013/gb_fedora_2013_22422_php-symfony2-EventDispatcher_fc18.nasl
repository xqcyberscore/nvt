###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for php-symfony2-EventDispatcher FEDORA-2013-22422
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.867125");
  script_version("$Revision: 9353 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2013-12-17 11:45:54 +0530 (Tue, 17 Dec 2013)");
  script_cve_id("CVE-2013-5958");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Fedora Update for php-symfony2-EventDispatcher FEDORA-2013-22422");

  tag_insight = "The Symfony2 Event Dispatcher component implements the Observer
(http://en.wikipedia.org/wiki/Observer_pattern) pattern in a simple and
effective way to make all these things possible and to make your projects
truly extensible.

Take a simple example from the Symfony2 HttpKernel component. Once a Response
object has been created, it may be useful to allow other elements in the system
to modify it (e.g. add some cache headers) before it's actually used. To make
this possible, the Symfony2 kernel throws an event - kernel.response. Here's
how it works:

* A listener (PHP object) tells a central dispatcher object that it wants to
  listen to the kernel.response event
* At some point, the Symfony2 kernel tells the dispatcher object to dispatch
  the kernel.response event, passing with it an Event object that has access to
  the Response object
* The dispatcher notifies (i.e. calls a method on) all listeners of the
  kernel.response event, allowing each of them to make modifications to the
  Response object.

Optional dependency: HttpKernel (php-symfony2-HttpKernel)
";

  tag_affected = "php-symfony2-EventDispatcher on Fedora 18";

  tag_solution = "Please Install the Updated Packages.";


  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name: "FEDORA", value: "2013-22422");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/pipermail/package-announce/2013-December/123258.html");
  script_tag(name: "summary" , value: "Check for the Version of php-symfony2-EventDispatcher");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms");
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

  if ((res = isrpmvuln(pkg:"php-symfony2-EventDispatcher", rpm:"php-symfony2-EventDispatcher~2.2.10~1.fc18", rls:"FC18")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
