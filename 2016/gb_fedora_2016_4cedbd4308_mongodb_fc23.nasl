###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for mongodb FEDORA-2016-4cedbd4308
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
  script_oid("1.3.6.1.4.1.25623.1.0.809929");
  script_version("$Revision: 4495 $");
  script_tag(name:"last_modification", value:"$Date: 2016-11-14 13:57:05 +0100 (Mon, 14 Nov 2016) $");
  script_tag(name:"creation_date", value:"2016-11-14 18:01:01 +0530 (Mon, 14 Nov 2016)");
  script_cve_id("CVE-2016-6494");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for mongodb FEDORA-2016-4cedbd4308");
  script_tag(name: "summary", value: "Check the version of mongodb");

  script_tag(name: "vuldetect", value: "Get the installed version with the help
  of detect NVT and check if the version is vulnerable or not.");

  script_tag(name: "insight", value: "Mongo (from 'humongous') is a
  high-performance, open source, schema-free document-oriented database.
  MongoDB is written in C++ and offers the following features:
  * Collection oriented storage: easy storage of object/JSON-style data
  * Dynamic queries
  * Full index support, including on inner objects and embedded arrays
  * Query profiling
  * Replication and fail-over support
  * Efficient storage of binary data including large objects (e.g. photos
    and videos)
  * Auto-sharding for cloud-level scalability (currently in early alpha)
  * Commercial Support Available

  A key goal of MongoDB is to bridge the gap between key/value stores
  (which are fast and highly scalable) and traditional RDBMS systems
  (which are deep in functionality).");

  script_tag(name: "affected", value: "mongodb on Fedora 23");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "FEDORA", value: "2016-4cedbd4308");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/2L5RBDAXPI5BR6RNME6K6WNDNSS5AJCI");
  script_tag(name:"solution_type", value:"VendorFix");
  script_summary("Check for the Version of mongodb");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("HostDetails/OS/cpe:/o:fedoraproject:fedora", "login/SSH/success", "ssh/login/release");
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

  if ((res = isrpmvuln(pkg:"mongodb", rpm:"mongodb~3.0.12~2.fc23", rls:"FC23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
