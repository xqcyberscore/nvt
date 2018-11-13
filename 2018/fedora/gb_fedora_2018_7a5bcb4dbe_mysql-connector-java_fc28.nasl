###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2018_7a5bcb4dbe_mysql-connector-java_fc28.nasl 12325 2018-11-13 02:48:44Z ckuersteiner $
#
# Fedora Update for mysql-connector-java FEDORA-2018-7a5bcb4dbe
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.875256");
  script_version("$Revision: 12325 $");
  script_cve_id("CVE-2018-3258");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-11-13 03:48:44 +0100 (Tue, 13 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-11-12 06:21:16 +0100 (Mon, 12 Nov 2018)");
  script_name("Fedora Update for mysql-connector-java FEDORA-2018-7a5bcb4dbe");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms");

  script_xref(name:"FEDORA", value:"2018-7a5bcb4dbe");
  script_xref(name:"URL" , value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/6RQUVEP3WC3TJ2TWC5FPWEPAMMT6DWIA");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mysql-connector-java'
  package(s) announced via the FEDORA-2018-7a5bcb4dbe advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"MySQL Connector/J is a native Java driver that converts JDBC (Java Database
Connectivity) calls into the network protocol used by the MySQL database.
It lets developers working with the Java programming language easily build
programs and applets that interact with MySQL and connect all corporate
data, even in a heterogeneous environment. MySQL Connector/J is a Type
IV JDBC driver and has a complete JDBC feature set that supports the
capabilities of MySQL.
");

  script_tag(name:"affected", value:"mysql-connector-java on Fedora 28.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "FC28")
{

  if ((res = isrpmvuln(pkg:"mysql-connector-java", rpm:"mysql-connector-java~8.0.13~1.fc28", rls:"FC28")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
