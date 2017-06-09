###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_postgresql_dos_vuln_win.nasl 6104 2017-05-11 09:03:48Z teissa $
#
# PostgreSQL Denial of Service Vulnerability (Windows)
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

tag_impact = "Successful exploitation will allow remote attackers to crash the server
  via a specially crafted SQL query.
  Impact Level: Application";

tag_affected = "PostgreSQL version 9.2.x before 9.2.3, 9.1.x before 9.1.8, 9.0.x
  before 9.0.12, 8.4.x before 8.4.16, and 8.3.x before 8.3.23";
tag_insight = "Input validation error within the 'enum_recv()' function of
  backend/utils/adt/enum.c";
tag_solution = "Upgrade to PostgreSQL 8.3.23, 8.4.16, 9.0.12, 9.1.8, 9.2.3 or later,
  For updates refer to http://www.postgresql.org/download/";
tag_summary = "This host is installed with PostgreSQL and is prone to denial
  of service vulnerability.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.803442";
CPE = "cpe:/a:postgresql:postgresql";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 6104 $");
  script_cve_id("CVE-2013-0255");
  script_bugtraq_id(57844);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-05-11 11:03:48 +0200 (Thu, 11 May 2017) $");
  script_tag(name:"creation_date", value:"2013-03-20 17:42:26 +0530 (Wed, 20 Mar 2013)");
  script_name("PostgreSQL Denial of Service Vulnerability (Windows)");
  script_xref(name : "URL" , value : "http://securitytracker.com/id?1028092");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/81917");
  script_xref(name : "URL" , value : "http://www.postgresql.org/support/security");

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

## Exit if its not windows
if(host_runs("Windows") != "yes"){
  exit(0);
}

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
if(isnull(pgsqlVer) ||  !(pgsqlVer =~ "^(8|9)")){
  exit(0);
}

## Check for vulnerable PostgreSQL versions
if(version_in_range(version:pgsqlVer, test_version:"8.3", test_version2:"8.3.22") ||
   version_in_range(version:pgsqlVer, test_version:"8.4", test_version2:"8.4.15") ||
   version_in_range(version:pgsqlVer, test_version:"9.0", test_version2:"9.0.11") ||
   version_in_range(version:pgsqlVer, test_version:"9.1", test_version2:"9.1.7") ||
   version_in_range(version:pgsqlVer, test_version:"9.2", test_version2:"9.2.2"))
{
  security_message(port:pgsqlPort);
  exit(0);
}
