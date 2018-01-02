###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for mantis FEDORA-2012-18299
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
tag_insight = "Mantis is a free popular web-based issue tracking system.
  It is written in the PHP scripting language and works with MySQL, MS SQL,
  and PostgreSQL databases and a web server.
  Almost any web browser should be able to function as a client.

  Documentation can be found in: /usr/share/doc/mantis-1.2.12

  When the package has finished installing, you will need to perform some
  additional configuration steps; these are described in:
  /usr/share/doc/mantis-1.2.12/README.Fedora";

tag_affected = "mantis on Fedora 16";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.fedoraproject.org/pipermail/package-announce/2012-November/093063.html");
  script_id(864887);
  script_version("$Revision: 8265 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-01 07:29:23 +0100 (Mon, 01 Jan 2018) $");
  script_tag(name:"creation_date", value:"2012-11-26 08:59:41 +0530 (Mon, 26 Nov 2012)");
  script_cve_id("CVE-2012-2691", "CVE-2012-2692", "CVE-2012-1118", "CVE-2012-1119",
                "CVE-2012-1120", "CVE-2012-1121", "CVE-2012-1122", "CVE-2012-1123",
                "CVE-2012-5522", "CVE-2012-5523");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_xref(name: "FEDORA", value: "2012-18299");
  script_name("Fedora Update for mantis FEDORA-2012-18299");

  script_tag(name: "summary" , value: "Check for the Version of mantis");
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

  if ((res = isrpmvuln(pkg:"mantis", rpm:"mantis~1.2.12~1.fc16", rls:"FC16")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
