###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for openstack-keystone FEDORA-2012-4960
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
tag_insight = "Keystone is a Python implementation of the OpenStack
  (<A HREF= &qt http://www.openstack.org &qt >http://www.openstack.org</A>) identity service API.

  Services included are:
  * Keystone    - identity store and authentication service
  * Auth_Token  - WSGI middleware that can be used to handle token auth protocol
                  (WSGI or remote proxy)
  * Auth_Basic  - Stub for WSGI middleware that will be used to handle basic auth
  * Auth_OpenID - Stub for WSGI middleware that will be used to handle openid
                  auth protocol
  * RemoteAuth  - WSGI middleware that can be used in services (like Swift, Nova,
                  and Glance) when Auth middleware is running remotely";

tag_affected = "openstack-keystone on Fedora 16";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.fedoraproject.org/pipermail/package-announce/2012-April/077041.html");
  script_id(864130);
  script_version("$Revision: 8336 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-09 08:01:48 +0100 (Tue, 09 Jan 2018) $");
  script_tag(name:"creation_date", value:"2012-04-11 10:42:42 +0530 (Wed, 11 Apr 2012)");
  script_cve_id("CVE-2012-1572");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_xref(name: "FEDORA", value: "2012-4960");
  script_name("Fedora Update for openstack-keystone FEDORA-2012-4960");

  script_tag(name: "summary" , value: "Check for the Version of openstack-keystone");
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

  if ((res = isrpmvuln(pkg:"openstack-keystone", rpm:"openstack-keystone~2011.3.1~3.fc16", rls:"FC16")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
