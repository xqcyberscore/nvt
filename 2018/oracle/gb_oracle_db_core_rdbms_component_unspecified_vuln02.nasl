###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_oracle_db_core_rdbms_component_unspecified_vuln02.nasl 10234 2018-06-18 09:06:34Z cfischer $
#
# Oracle Database Server 'Core RDBMS' Component Unspecified Vulnerability-02
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.812737");
  script_version("$Revision: 10234 $");
  script_cve_id("CVE-2018-2575");
  script_bugtraq_id(102547);
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-06-18 11:06:34 +0200 (Mon, 18 Jun 2018) $");
  script_tag(name:"creation_date", value:"2018-01-19 16:41:33 +0530 (Fri, 19 Jan 2018)");
  script_name("Oracle Database Server 'Core RDBMS' Component Unspecified Vulnerability-02");

  script_tag(name:"summary", value:"This host is running Oracle Database Server
  and is prone to an unspecified security vulnerability.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name:"insight", value:"The flaw is due to an unspecified error in
  component 'Core RDBMS'.");

  script_tag(name:"impact", value:"Successfully exploitation will allow remote
  attackers to affect confidentiality via unknown vectors.

  Impact Level: Application");

  script_tag(name:"affected", value:"Oracle Database Server versions
  11.2.0.4, 12.2.0.1");

  script_tag(name:"solution", value:"Apply patches from below link,
  http://www.oracle.com/technetwork/security-advisory/cpujan2018-3236628.html");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name : "URL" , value : "http://www.oracle.com/technetwork/security-advisory/cpujan2018-3236628.html");
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Databases");
  script_dependencies("oracle_tnslsnr_version.nasl", "os_detection.nasl");
  script_mandatory_keys("OracleDatabaseServer/installed", "Host/runs_windows"); # From the advisory: Applicable only to Windows platform.
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!dbport = get_app_port(cpe:CPE)){
  exit(0);
}

if(!infos = get_app_version_and_location(cpe:CPE, port:dbport, exit_no_version:TRUE)) exit(0);
dbVer = infos['version'];
path = infos['location'];

if(dbVer == "11.2.0.4" ||
   dbVer == "12.2.0.1")
{
  report = report_fixed_ver(installed_version:dbVer, fixed_version:"Apply the appropriate patch", install_path:path);
  security_message(data:report, port:dbport);
  exit(0);
}

exit(0);
