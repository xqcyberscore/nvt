###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2018_48b73ed393_jetty_fc28.nasl 10558 2018-07-20 14:08:23Z santu $
#
# Fedora Update for jetty FEDORA-2018-48b73ed393
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.874809");
  script_version("$Revision: 10558 $");
  script_tag(name:"last_modification", value:"$Date: 2018-07-20 16:08:23 +0200 (Fri, 20 Jul 2018) $");
  script_tag(name:"creation_date", value:"2018-07-15 06:04:25 +0200 (Sun, 15 Jul 2018)");
  script_cve_id("CVE-2017-7656", "CVE-2017-7657", "CVE-2017-7658", "CVE-2018-12536");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for jetty FEDORA-2018-48b73ed393");
  script_tag(name:"summary", value:"Check the version of jetty");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present 
on the target host.");
  script_tag(name:"insight", value:"Jetty is a 100% Java HTTP Server and 
Servlet Container. This means that you do not need to configure and run a 
separate web server (like Apache) in order to use Java, servlets and JSPs to 
generate dynamic content. Jetty is a fully featured web server for static 
and dynamic content. Unlike separate server/container solutions, this means 
that your web server and web application run in the same process, without 
interconnection overheads and complications. Furthermore, as a pure java 
component, Jetty can be simply included in your application for demonstration, 
distribution or deployment. Jetty is available on all Java supported platforms.
");
  script_tag(name:"affected", value:"jetty on Fedora 28");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"FEDORA", value:"2018-48b73ed393");
  script_xref(name:"URL" , value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/QJNLQI54CY5A2GFZ4PDZTIGKMXJJUSKM");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
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

if(release == "FC28")
{

  if ((res = isrpmvuln(pkg:"jetty", rpm:"jetty~9.4.11~2.v20180605.fc28", rls:"FC28")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
