###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_oracle_db_ojvm_component_unspecified_vuln.nasl 7597 2017-10-27 12:23:39Z asteins $
#
# Oracle Database Server 'OJVM' Component Unspecified Vulnerability
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.811532");
  script_version("$Revision: 7597 $");
  script_cve_id("CVE-2017-10202", "CVE-2017-10321", "CVE-2017-10190", "CVE-2017-10292");
  script_bugtraq_id(99865, 101329, 101335, 101350);
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-10-27 14:23:39 +0200 (Fri, 27 Oct 2017) $");
  script_tag(name:"creation_date", value:"2017-07-19 12:14:58 +0530 (Wed, 19 Jul 2017)");
  script_name("Oracle Database Server 'OJVM' Component Unspecified Vulnerability");

  script_tag(name:"summary", value:"This host is running  Oracle Database Server
  and is prone to multiple unspecified security vulnerabilities.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name:"insight", value:"Multiple flaws are due to multiple 
  unspecified errors in components 'Core RDBMS', 'Spatial (Apache Groovy)', 
  'Java VM', 'WLM (Apache Tomcat)', 'XML Database', 'RDBMS Security' and 
  'OJVM' components.");

  script_tag(name:"impact", value:"Successfully exploitation will allow remote
  attackers to affect confidentiality, integrity, and availability
  via unknown vectors.

  Impact Level: Application");

  script_tag(name:"affected", value:"Oracle Database Server versions
  11.2.0.4, 12.1.0.2, 12.2.0.1");

  script_tag(name:"solution", value:"Apply patches from below links,
  http://www.oracle.com/technetwork/security-advisory/cpujul2017-3236622.html
  http://www.oracle.com/technetwork/security-advisory/cpuoct2017-3236626.html");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name : "URL" , value : "http://www.oracle.com/technetwork/security-advisory/cpujul2017-3236622.html");
  script_xref(name : "URL" , value : "http://www.oracle.com/technetwork/security-advisory/cpuoct2017-3236626.html");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Databases");
  script_dependencies("oracle_tnslsnr_version.nasl");
  script_mandatory_keys("OracleDatabaseServer/installed");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

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

if(dbVer == "11.2.0.4" ||
   dbVer == "12.1.0.2" ||
   dbVer == "12.2.0.1")
{
  report = report_fixed_ver(installed_version:dbVer, fixed_version:"Apply the appropriate patch");
  security_message(data:report, port:dbPort);
  exit(0);
}
