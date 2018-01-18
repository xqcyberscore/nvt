###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for mantis FEDORA-2013-4319
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
tag_insight = "Mantis is a free popular web-based issue tracking system.
  It is written in the PHP scripting language and works with MySQL, MS SQL,
  and PostgreSQL databases and a web server.
  Almost any web browser should be able to function as a client.

  Documentation can be found in: /usr/share/doc/mantis-1.2.14

  When the package has finished installing, you will need to perform some
  additional configuration steps; these are described in:
  /usr/share/doc/mantis-1.2.14/README.Fedora";


tag_affected = "mantis on Fedora 18";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.fedoraproject.org/pipermail/package-announce/2013-April/101180.html");
  script_id(865510);
  script_version("$Revision: 8456 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-18 07:58:40 +0100 (Thu, 18 Jan 2018) $");
  script_tag(name:"creation_date", value:"2013-04-02 12:24:13 +0530 (Tue, 02 Apr 2013)");
  script_cve_id("CVE-2013-0197", "CVE-2013-1883");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_xref(name: "FEDORA", value: "2013-4319");
  script_name("Fedora Update for mantis FEDORA-2013-4319");

  script_tag(name: "summary" , value: "Check for the Version of mantis");
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

if(release == "FC18")
{

  if ((res = isrpmvuln(pkg:"mantis", rpm:"mantis~1.2.14~1.fc18", rls:"FC18")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
