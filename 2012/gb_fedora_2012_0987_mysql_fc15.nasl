###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for mysql FEDORA-2012-0987
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
tag_affected = "mysql on Fedora 15";
tag_insight = "MySQL is a multi-user, multi-threaded SQL database server. MySQL is a
  client/server implementation consisting of a server daemon (mysqld)
  and many different client programs and libraries. The base package
  contains the standard MySQL client programs and generic MySQL files.";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.fedoraproject.org/pipermail/package-announce/2012-February/073182.html");
  script_id(863725);
  script_version("$Revision: 8253 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-28 07:29:51 +0100 (Thu, 28 Dec 2017) $");
  script_tag(name:"creation_date", value:"2012-02-13 16:22:45 +0530 (Mon, 13 Feb 2012)");
  script_cve_id("CVE-2011-2262", "CVE-2012-0075", "CVE-2012-0112", "CVE-2012-0113",
                "CVE-2012-0114", "CVE-2012-0115", "CVE-2012-0116", "CVE-2012-0117",
                "CVE-2012-0118", "CVE-2012-0119", "CVE-2012-0120", "CVE-2012-0484",
                "CVE-2012-0485", "CVE-2012-0486", "CVE-2012-0487", "CVE-2012-0488",
                "CVE-2012-0489", "CVE-2012-0490", "CVE-2012-0491", "CVE-2012-0492",
                "CVE-2012-0493", "CVE-2012-0494", "CVE-2012-0495", "CVE-2012-0496");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:P");
  script_xref(name: "FEDORA", value: "2012-0987");
  script_name("Fedora Update for mysql FEDORA-2012-0987");

  script_tag(name: "summary" , value: "Check for the Version of mysql");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms");
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
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

if(release == "FC15")
{

  if ((res = isrpmvuln(pkg:"mysql", rpm:"mysql~5.5.20~1.fc15", rls:"FC15")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
