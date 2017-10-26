###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_postgresql_dos_vuln_apr13_win.nasl 7548 2017-10-24 12:06:02Z cfischer $
#
# PostgreSQL Denial of Service Vulnerability - Apr13 (Windows)
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary
  SQL query, gain access or manipulate arbitrary files, and cause denial
  of service.
  Impact Level: Application";

tag_affected = "PostgreSQL version 9.2.x before 9.2.4, 9.1.x before 9.1.9, and
  9.0.x before 9.0.13";
tag_insight = "Improper validation of connection request that contains database name
  begins with the '-' symbol";
tag_solution = "Upgrade to PostgreSQL 9.0.13, 9.1.9, 9.2.4 or later,
  For updates refer to http://www.postgresql.org/download";
tag_summary = "This host is installed with PostgreSQL and is prone to denial
  of service vulnerability.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.803473";
CPE = "cpe:/a:postgresql:postgresql";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 7548 $");
  script_cve_id("CVE-2013-1899");
  script_bugtraq_id(58876);
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-10-24 14:06:02 +0200 (Tue, 24 Oct 2017) $");
  script_tag(name:"creation_date", value:"2013-04-09 16:49:46 +0530 (Tue, 09 Apr 2013)");
  script_name("PostgreSQL Denial of Service Vulnerability - Apr13 (Windows)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/52837");
  script_xref(name : "URL" , value : "http://securitytracker.com/id?1028387");
  script_xref(name : "URL" , value : "http://www.postgresql.org/about/news/1456");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("postgresql_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/postgresql", 5432);
  script_mandatory_keys("PostgreSQL/installed","Host/runs_windows");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("misc_func.inc");
include("version_func.inc");
include("host_details.inc");

## Variable Initialization
pgsqlPort = "";
pgsqlVer = "";

## Get the default port
pgsqlPort = get_app_port(cpe:CPE, nvt:SCRIPT_OID);
if(!pgsqlPort){
  pgsqlPort = 5432;
}

## Check the port status
if(!get_port_state(pgsqlPort)){
  exit(0);
}

## Get the PostgreSQL version
pgsqlVer = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:pgsqlPort);
if(isnull(pgsqlVer) ||  !(pgsqlVer =~ "^(9\.(0|1|2))")){
  exit(0);
}

## Check for vulnerable PostgreSQL versions
if(version_in_range(version:pgsqlVer, test_version:"9.0", test_version2:"9.0.12") ||
   version_in_range(version:pgsqlVer, test_version:"9.1", test_version2:"9.1.8") ||
   version_in_range(version:pgsqlVer, test_version:"9.2", test_version2:"9.2.3"))
{
  security_message(port:pgsqlPort);
  exit(0);
}
