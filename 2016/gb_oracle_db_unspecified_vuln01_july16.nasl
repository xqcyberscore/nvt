###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_oracle_db_unspecified_vuln01_july16.nasl 7497 2017-10-19 07:06:06Z santu $
#
# Oracle Database Server Unspecified Vulnerability -01 July16
#
# Authors:
# Tushar Khelge <ktushar@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.808703");
  script_version("$Revision: 7497 $");
  script_cve_id("CVE-2016-3479", "CVE-2016-5555", "CVE-2016-5505", "CVE-2016-5498", 
                "CVE-2016-5499", "CVE-2016-3562", "CVE-2017-3310", "CVE-2017-3486", 
                "CVE-2016-2183", "CVE-2014-3566", "CVE-2017-10261");
  script_bugtraq_id(91898, 93615, 93613, 93620, 93629, 93640, 95481, 92630, 70574, 101344);
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-10-19 09:06:06 +0200 (Thu, 19 Oct 2017) $");
  script_tag(name:"creation_date", value:"2016-07-21 18:47:32 +0530 (Thu, 21 Jul 2016)");
  script_name("Oracle Database Server Unspecified Vulnerability -01 July16");

  script_tag(name:"summary", value:"This host is running  Oracle Database Server
  and is prone multiple unspecified vulnerabilities.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name:"insight", value:"The multiple flaws are due to,

  - Multiple unspecified errors.

  - Multiple unspecified errors related to components 'DBMS_LDAP',
    'Real Application Clusters' and 'XML Database' components.");

  script_tag(name:"impact", value:"Successfully exploitation will allow remote
  authenticated attackers to affect confidentiality, integrity, and availability
  via unknown vectors.

  Impact Level: Application");

  script_tag(name:"affected", value:"Oracle Database Server versions
  11.2.0.4 and 12.1.0.2");

  script_tag(name:"solution", value:"Apply patches from below link,
  http://www.oracle.com/technetwork/security-advisory/cpujul2016-2881720.html
  http://www.oracle.com/technetwork/security-advisory/cpuoct2016-2881722.html
  http://www.oracle.com/technetwork/security-advisory/cpujan2017-2881727.html
  http://www.oracle.com/technetwork/security-advisory/cpujul2017-3236622.html
  http://www.oracle.com/technetwork/security-advisory/cpuapr2017-3236618.html
  http://www.oracle.com/technetwork/security-advisory/cpuoct2017-3236626.html");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name : "URL" , value : "http://www.oracle.com/technetwork/security-advisory/cpujul2016-2881720.html");
  script_xref(name : "URL" , value : "http://www.oracle.com/technetwork/security-advisory/cpuoct2016-2881722.html");
  script_xref(name : "URL" , value : "http://www.oracle.com/technetwork/security-advisory/cpujan2017-2881727.html");
  script_xref(name : "URL" , value : "http://www.oracle.com/technetwork/security-advisory/cpujul2017-3236622.html");
  script_xref(name : "URL" , value : "http://www.oracle.com/technetwork/security-advisory/cpuapr2017-3236618.html");
  script_xref(name : "URL" , value : "http://www.oracle.com/technetwork/security-advisory/cpuoct2017-3236626.html");
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
if(version_is_equal(version:dbVer, test_version:"11.2.0.4") ||
   version_is_equal(version:dbVer, test_version:"12.1.0.2"))
{
  report = report_fixed_ver(installed_version:dbVer, fixed_version:"Apply the appropriate patch");
  security_message(data:report, port:dbPort);
  exit(0);
}
