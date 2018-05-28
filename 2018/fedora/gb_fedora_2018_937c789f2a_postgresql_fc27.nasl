###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2018_937c789f2a_postgresql_fc27.nasl 9962 2018-05-25 13:08:04Z santu $
#
# Fedora Update for postgresql FEDORA-2018-937c789f2a
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
  script_oid("1.3.6.1.4.1.25623.1.0.874590");
  script_version("$Revision: 9962 $");
  script_tag(name:"last_modification", value:"$Date: 2018-05-25 15:08:04 +0200 (Fri, 25 May 2018) $");
  script_tag(name:"creation_date", value:"2018-05-22 05:08:38 +0200 (Tue, 22 May 2018)");
  script_cve_id("CVE-2017-15097", "CVE-2018-1115");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for postgresql FEDORA-2018-937c789f2a");
  script_tag(name:"summary", value:"Check the version of postgresql");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present 
on the target host.");
  script_tag(name:"insight", value:"PostgreSQL is an advanced Object-Relational 
database management system (DBMS). The base postgresql package contains the client 
programs that you&#39 ll need to access a PostgreSQL DBMS server, as well as HTML 
documentation for the whole system.  These client programs can be located on the 
same machine as the PostgreSQL server, or on a remote machine that accesses a 
PostgreSQL server over a network connection.  The PostgreSQL server can be found 
in the postgresql-server sub-package.
");
  script_tag(name:"affected", value:"postgresql on Fedora 27");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"FEDORA", value:"2018-937c789f2a");
  script_xref(name:"URL" , value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/7WZYWTXOZYTG4RUI5ZIF45RBRYQ4QRXO");
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

if(release == "FC27")
{

  if ((res = isrpmvuln(pkg:"postgresql", rpm:"postgresql~9.6.9~1.fc27", rls:"FC27")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
