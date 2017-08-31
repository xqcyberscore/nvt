###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for struts FEDORA-2016-21bd6a33af
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.808523");
  script_version("$Revision: 6631 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-10 08:36:10 +0200 (Mon, 10 Jul 2017) $");
  script_tag(name:"creation_date", value:"2016-07-02 06:38:44 +0200 (Sat, 02 Jul 2016)");
  script_cve_id("CVE-2016-1181", "CVE-2016-1182");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for struts FEDORA-2016-21bd6a33af");
  script_tag(name: "summary", value: "Check the version of struts");

  script_tag(name: "vuldetect", value: "Get the installed version with the help
  of detect NVT and check if the version is vulnerable or not.");

  script_tag(name: "insight", value: "Welcome to the Struts Framework! The goal
  of this project is to provide an open source framework useful in building
  web applications with Java Servlet and JavaServer Pages (JSP) technology.
  Struts encourages application architectures based on the Model-View-Controller
  (MVC) design paradigm, colloquially known as Model 2 in discussions on various
  servlet and JSP related mailing lists.
  Struts includes the following primary areas of functionality:
  A controller servlet that dispatches requests to appropriate Action
  classes provided by the application developer.
  JSP custom tag libraries, and associated support in the controller
  servlet, that assists developers in creating interactive form-based
  applications.
  Utility classes to support XML parsing, automatic population of
  JavaBeans properties based on the Java reflection APIs, and
  internationalization of prompts and messages.");

  script_tag(name: "affected", value: "struts on Fedora 23");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "FEDORA", value: "2016-21bd6a33af");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/Z74JLHOBT3TZVPAHD7FUPFP3LYAOQTR7");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
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

if(release == "FC23")
{

  if ((res = isrpmvuln(pkg:"struts", rpm:"struts~1.3.10~18.fc23", rls:"FC23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
