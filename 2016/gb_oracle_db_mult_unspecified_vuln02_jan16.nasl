###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_oracle_db_mult_unspecified_vuln02_jan16.nasl 5813 2017-03-31 09:01:08Z teissa $
#
# Oracle Database Server Multiple Unspecified Vulnerabilities -02 Jan16
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
  script_oid("1.3.6.1.4.1.25623.1.0.807036");
  script_version("$Revision: 5813 $");
  script_cve_id("CVE-2015-4857", "CVE-2015-2595", "CVE-2016-0677", "CVE-2015-0204");
  script_bugtraq_id(77180, 75879, 71936);
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-03-31 11:01:08 +0200 (Fri, 31 Mar 2017) $");
  script_tag(name:"creation_date", value:"2016-01-22 13:02:26 +0530 (Fri, 22 Jan 2016)");
  script_name("Oracle Database Server Multiple Unspecified Vulnerabilities -02 Jan16");

  script_tag(name:"summary", value:"This host is running  Oracle Database Server
  and is prone to multiple unspecified vulnerabilities.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name:"insight", value:"Multiple flaws are due to:
  - Multiple unspecified vulnerabilities in RDBMS component.
  - An unspecified vulnerability in Oracle OLAP component.");

  script_tag(name:"impact", value:"Successfully exploitation will allow remote
  authenticated attackers to affect confidentiality, integrity, and availability
  via unknown vectors.

  Impact Level: Application");

  script_tag(name:"affected", value:"Oracle Database Server versions
  12.1.0.1, and 12.1.0.2");

  script_tag(name:"solution", value:"Apply patches from below link,
  http://www.oracle.com/technetwork/topics/security/cpujul2015-2367936.html
  http://www.oracle.com/technetwork/security-advisory/cpujul2016-2881720.html");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name : "URL" , value : "http://www.oracle.com/technetwork/topics/security/cpujul2015-2367936.html");
  script_xref(name : "URL" , value : "http://www.oracle.com/technetwork/security-advisory/cpujul2016-2881720.html");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
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
if(dbVer =~ "^(12\.1)")
{
  if(version_is_equal(version:dbVer, test_version:"12.1.0.1") ||
     version_is_equal(version:dbVer, test_version:"12.1.0.2"))
  {
    report = report_fixed_ver(installed_version:dbVer, fixed_version:"Apply the appropriate patch");
    security_message(data:report, port:dbPort);
    exit(0);
  }
}
