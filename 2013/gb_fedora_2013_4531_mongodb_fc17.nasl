###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for mongodb FEDORA-2013-4531
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
tag_insight = "Mongo (from humongous) is a high-performance, open source, schema-free
  document-oriented database. MongoDB is written in C++ and offers the following
  features:
      * Collection oriented storage: easy storage of object/JSON-style data
      * Dynamic queries
      * Full index support, including on inner objects and embedded arrays
      * Query profiling
      * Replication and fail-over support
      * Efficient storage of binary data including large objects (e.g. photos
      and videos)
      * Auto-sharding for cloud-level scalability (currently in early alpha)
      * Commercial Support Available

  A key goal of MongoDB is to bridge the gap between key/value stores (which are
  fast and highly scalable) and traditional RDBMS systems (which are deep in
  functionality).";


tag_affected = "mongodb on Fedora 17";
tag_solution = "Please Install the Updated Packages.";

if(description)
{
  script_id(865533);
  script_version("$Revision: 8650 $");
  script_tag(name:"last_modification", value:"$Date: 2018-02-03 13:16:59 +0100 (Sat, 03 Feb 2018) $");
  script_tag(name:"creation_date", value:"2013-04-08 10:33:11 +0530 (Mon, 08 Apr 2013)");
  script_cve_id("CVE-2013-1892");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_name("Fedora Update for mongodb FEDORA-2013-4531");

  script_xref(name: "FEDORA", value: "2013-4531");
  script_xref(name: "URL" , value: "http://lists.fedoraproject.org/pipermail/package-announce/2013-April/101679.html");
  script_tag(name: "summary" , value: "Check for the Version of mongodb");
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

  if ((res = isrpmvuln(pkg:"mongodb", rpm:"mongodb~2.2.3~4.fc17", rls:"FC17")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
