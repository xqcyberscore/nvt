###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for jetty FEDORA-2017-03954b6dc4
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
  script_oid("1.3.6.1.4.1.25623.1.0.872871");
  script_version("$Revision: 6733 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-14 16:39:43 +0200 (Fri, 14 Jul 2017) $");
  script_tag(name:"creation_date", value:"2017-07-14 15:55:02 +0530 (Fri, 14 Jul 2017)");
  script_cve_id("CVE-2017-9735");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for jetty FEDORA-2017-03954b6dc4");
  script_tag(name: "summary", value: "Check the version of jetty");
  script_tag(name: "vuldetect", value: "Get the installed version with the help 
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "Jetty is a 100% Java HTTP Server and 
Servlet Container. This means that you do not need to configure and run a 
separate web server (like Apache) in order to use Java, servlets and JSPs 
to generate dynamic content. Jetty is a fully featured web server for static 
and dynamic content. Unlike separate server/container solutions, this means 
that your web server and web application run in the same process, without 
interconnection overheads and complications. Furthermore, as a pure java 
component, Jetty can be simply included in your application for demonstration, 
distribution or deployment. Jetty is available on all Java supported platforms.");
  script_tag(name: "affected", value: "jetty on Fedora 25");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "FEDORA", value: "2017-03954b6dc4");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/JBJJEXEL4I7H623UZTKILCUYXF5LVODW");
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

  if ((res = isrpmvuln(pkg:"jetty", rpm:"jetty~9.4.6~1.v20170531.fc25", rls:"FC25")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
