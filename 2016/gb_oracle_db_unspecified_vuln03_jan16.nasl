###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_oracle_db_unspecified_vuln03_jan16.nasl 5588 2017-03-16 10:00:36Z teissa $
#
# Oracle Database Server Unspecified Vulnerability -03 Jan16
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:oracle:database_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807043");
  script_version("$Revision: 5588 $");
  script_cve_id("CVE-2015-0479");
  script_bugtraq_id(74084);
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-03-16 11:00:36 +0100 (Thu, 16 Mar 2017) $");
  script_tag(name:"creation_date", value:"2016-01-25 14:59:25 +0530 (Mon, 25 Jan 2016)");
  script_name("Oracle Database Server Unspecified Vulnerability -03 Jan16");

  script_tag(name:"summary", value:"This host is running  Oracle Database Server
  and is prone to unspecified vulnerability.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name:"insight", value:"The flaw is due to an unspecified
  error in the XDK and XDB - XML Database component.");

  script_tag(name:"impact", value:"Successfully exploitation will allow remote
  authenticated attackers to affect availability via unknown vectors.

  Impact Level: Application");

  script_tag(name:"affected", value:"Oracle Database Server versions
  11.2.0.3, 11.2.0.4, and 12.1.0.1");

  script_tag(name:"solution", value:"Apply patches from below link,
  http://www.oracle.com/technetwork/topics/security/cpuapr2015-2365600.html");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name : "URL" , value : "http://www.oracle.com/technetwork/topics/security/cpuapr2015-2365600.html");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Databases");
  script_dependencies("oracle_tnslsnr_version.nasl");
  script_mandatory_keys("OracleDatabaseServer/installed");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");
include("global_settings.inc");

## Variable Initialization
dbPort = "";
dbVer = "";

## Get port
if(!dbport = get_app_port(cpe:CPE)){
  exit(0);
}

## Get the version
if(!dbVer = get_app_version(cpe:CPE, port:dbPort)){
  exit(0);
}

## Check for vulnerable version
if(version_is_equal(version:dbVer, test_version:"12.1.0.1") ||
   version_is_equal(version:dbVer, test_version:"11.2.0.3") ||
   version_is_equal(version:dbVer, test_version:"11.2.0.4"))
{
  report = report_fixed_ver(installed_version:dbVer, fixed_version:"Apply the appropriate patch");
  security_message(data:report, port:dbPort);
  exit(0);
}
