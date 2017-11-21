###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mysql_server_optimizer_unspecified_vuln.nasl 7838 2017-11-21 05:43:57Z santu $
#
# MySQL Server Optimizer Component Unspecified Vulnerability
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

tag_impact = "Successful exploitation could allow remote authenticated users to affect
  availability via unknown vectors.
  Impact Level: Application";

tag_affected = "MySQL version 5.5.x before 5.5.20";
tag_insight = "Unspecified error in MySQL Server component related to Server Optimizer.";
tag_solution = "Apply the patch from the below link,
  http://www.oracle.com/technetwork/topics/security/cpuapr2012-366314.html";
tag_summary = "The host is running MySQL and is prone to unspecified
  vulnerability.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.803800";
CPE = "cpe:/a:mysql:mysql";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 7838 $");
  script_cve_id("CVE-2012-1696");
  script_bugtraq_id(53071);
  script_tag(name:"last_modification", value:"$Date: 2017-11-21 06:43:57 +0100 (Tue, 21 Nov 2017) $");
  script_tag(name:"creation_date", value:"2013-06-04 13:19:03 +0530 (Tue, 04 Jun 2013)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_name("MySQL Server Optimizer Component Unspecified Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/48890");
  script_xref(name : "URL" , value : "http://www.oracle.com/technetwork/topics/security/cpuapr2012-366314.html#AppendixMSQL");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_tag(name:"qod_type", value:"remote_banner");
  script_dependencies("mysql_version.nasl", "os_detection.nasl");
  script_require_ports("Services/mysql", 3306);
  script_mandatory_keys("MySQL/installed","Host/runs_windows");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

## Variable Initialization
sqlPort = "";
mysqlVer = "";

sqlPort = get_app_port(cpe:CPE, nvt:SCRIPT_OID);
if(!sqlPort){
  sqlPort = 3306;
}

if(!get_port_state(sqlPort)){
  exit(0);
}

mysqlVer = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:sqlPort);
if(mysqlVer && mysqlVer =~ "^(5\.5)")
{
  if(version_in_range(version:mysqlVer, test_version:"5.5", test_version2:"5.5.19"))
  {
    security_message(sqlPort);
    exit(0);
  }
}
