###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_solarwinds_orion_npm_mult_vuln.nasl 8367 2018-01-11 07:32:43Z cfischer $
#
# SolarWinds Orion NPM Multiple Vulnerabilities
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

CPE = "cpe:/a:solarwinds:orion_network_performance_monitor";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812219");
  script_version("$Revision: 8367 $");
  script_cve_id("CVE-2017-9538", "CVE-2017-9537", "CVE-2017-9539");
  script_bugtraq_id(101066, 101071);
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-01-11 08:32:43 +0100 (Thu, 11 Jan 2018) $");
  script_tag(name:"creation_date", value:"2017-11-21 11:43:13 +0530 (Tue, 21 Nov 2017)");
  script_name("SolarWinds Orion NPM Multiple Vulnerabilities");

  script_tag(name:"summary", value:"This host is installed with SolarWinds Orion NPM 
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - An incorrect implementation of a directory-traversal protection mechanism.

  - An improper validation of user supplied input in the 'Add Node' function.

  - An unspecified error.");

  script_tag(name:"impact", value:"Successfully exploiting this issue allow
  remote attackers to execute arbitrary script code in the browser of an
  unsuspecting user in the context of the affected site. This may allow the
  attacker to steal cookie-based authentication credentials and launch other
  attacks and cause denial-of-service conditions, denying service to legitimate 
  users.

  Impact Level: Application");

  script_tag(name:"affected", value:"SolarWinds Orion NPM version 12.0.15300.90.");

  script_tag(name:"solution", value:"Apply the hotfix SolarWinds Orion Platform 
  2017.3 Hotfix 1. For updates refer to https://support.solarwinds.com");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/541263/100/0/threaded");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/541262/100/0/threaded");
  script_xref(name : "URL" , value : "https://support.solarwinds.com/Success_Center/Orion_Platform/Orion_Documentation/Orion_Platform_2017.3_Hotfix_1");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_orion_npm_detect.nasl");
  script_mandatory_keys("orion_npm/installed");
  script_require_ports("Services/www", 8787);
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

npmPort = "";
npmVer = "";
npmPath = "";

if(!npmPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!infos = get_app_version_and_location(cpe:CPE, port:npmPort, exit_no_version:TRUE)) exit(0);
npmVer = infos['version'];
npmPath = infos['location'];

if(version_is_equal(version:npmVer, test_version:"12.0.15300.90"))
{
  report = report_fixed_ver(installed_version:npmVer, fixed_version:"Apply SolarWinds Orion Platform 2017.3 Hotfix 1", install_path:npmPath);
  security_message(port:npmPort, data:report);
  exit(0);
}
exit(0);
