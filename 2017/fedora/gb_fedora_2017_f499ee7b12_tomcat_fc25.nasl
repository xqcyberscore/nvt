###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2017_f499ee7b12_tomcat_fc25.nasl 7920 2017-11-28 07:49:35Z asteins $
#
# Fedora Update for tomcat FEDORA-2017-f499ee7b12
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
  script_oid("1.3.6.1.4.1.25623.1.0.873711");
  script_version("$Revision: 7920 $");
  script_tag(name:"last_modification", value:"$Date: 2017-11-28 08:49:35 +0100 (Tue, 28 Nov 2017) $");
  script_tag(name:"creation_date", value:"2017-11-23 08:09:37 +0100 (Thu, 23 Nov 2017)");
  script_cve_id("CVE-2017-12617", "CVE-2017-12615");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for tomcat FEDORA-2017-f499ee7b12");
  script_tag(name: "summary", value: "Check the version of tomcat");
  script_tag(name: "vuldetect", value: "Get the installed version with the help 
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "Tomcat is the servlet container that is 
used in the official Reference Implementation for the Java Servlet and JavaServer 
Pages technologies. The Java Servlet and JavaServer Pages specifications are 
developed by Sun under the Java Community Process.

Tomcat is developed in an open and participatory environment and
released under the Apache Software License version 2.0. Tomcat is intended
to be a collaboration of the best-of-breed developers from around the world.
");
  script_tag(name: "affected", value: "tomcat on Fedora 25");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "FEDORA", value: "2017-f499ee7b12");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/N55R66XGBTPQ3X4NTIVLL4DHL5B3TBGW");
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

  if ((res = isrpmvuln(pkg:"tomcat", rpm:"tomcat~8.0.47~1.fc25", rls:"FC25")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
