###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2018_a510417d97_postgresql_fc28.nasl 12362 2018-11-15 09:45:28Z santu $
#
# Fedora Update for postgresql FEDORA-2018-a510417d97
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
  script_oid("1.3.6.1.4.1.25623.1.0.875267");
  script_version("$Revision: 12362 $");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-11-15 10:45:28 +0100 (Thu, 15 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-11-14 06:35:09 +0100 (Wed, 14 Nov 2018)");
  script_name("Fedora Update for postgresql FEDORA-2018-a510417d97");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms");

  script_xref(name:"FEDORA", value:"2018-a510417d97");
  script_xref(name:"URL" , value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/U3VZCOJZGFKBIKLJ3MO23QA4T2XU2NYT");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'postgresql'
  package(s) announced via the FEDORA-2018-a510417d97 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"PostgreSQL is an advanced Object-Relational database management system (DBMS).
The base postgresql package contains the client programs that you&#39 ll need to
access a PostgreSQL DBMS server, as well as HTML documentation for the whole
system.  These client programs can be located on the same machine as the
PostgreSQL server, or on a remote machine that accesses a PostgreSQL server
over a network connection.  The PostgreSQL server can be found in the
postgresql-server sub-package.
");

  script_tag(name:"affected", value:"postgresql on Fedora 28.");

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

  if ((res = isrpmvuln(pkg:"postgresql", rpm:"postgresql~10.6~1.fc28", rls:"FC28")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
