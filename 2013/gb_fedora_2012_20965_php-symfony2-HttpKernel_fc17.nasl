###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for php-symfony2-HttpKernel FEDORA-2012-20965
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
tag_insight = "HttpKernel provides the building blocks to create flexible and fast
  HTTP-based frameworks.

  It takes a Request as an input and should return a Response as an output.
  Using this interface makes your code compatible with all frameworks using
  the Symfony2 components. And this will give you many cool features for free.

  Optional dependencies: memcache, memcached, mongo";


tag_affected = "php-symfony2-HttpKernel on Fedora 17";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.fedoraproject.org/pipermail/package-announce/2013-January/095334.html");
  script_id(864969);
  script_version("$Revision: 8466 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-19 07:58:30 +0100 (Fri, 19 Jan 2018) $");
  script_tag(name:"creation_date", value:"2013-01-04 12:34:04 +0530 (Fri, 04 Jan 2013)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_xref(name: "FEDORA", value: "2012-20965");
  script_name("Fedora Update for php-symfony2-HttpKernel FEDORA-2012-20965");

  script_tag(name: "summary" , value: "Check for the Version of php-symfony2-HttpKernel");
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

if(release == "FC17")
{

  if ((res = isrpmvuln(pkg:"php-symfony2-HttpKernel", rpm:"php-symfony2-HttpKernel~2.1.6~1.fc17", rls:"FC17")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
