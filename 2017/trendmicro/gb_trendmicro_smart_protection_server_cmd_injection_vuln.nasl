###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_trendmicro_smart_protection_server_cmd_injection_vuln.nasl 7555 2017-10-25 06:39:30Z emoss $
#
# Trend Micro Smart Protection Server Command Injection Vulnerability
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
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

CPE = "cpe:/a:trendmicro:smart_protection_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811916");
  script_version("$Revision: 7555 $");
  script_cve_id("CVE-2017-11395");
  script_bugtraq_id(100461);
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-10-25 08:39:30 +0200 (Wed, 25 Oct 2017) $");
  script_tag(name:"creation_date", value:"2017-10-24 12:42:06 +0530 (Tue, 24 Oct 2017)");
  script_name("Trend Micro Smart Protection Server Command Injection Vulnerability");

  script_tag(name:"summary", value:"This host is installed with Trend Micro
  Smart Protection Server and is prone to command injection vulnerability.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name:"insight", value:"The flaw exits due to the cm_agent.php script
  did not sanitize input parameters before executing a system command.");

  script_tag(name:"impact", value:"Successful exploitation will allow 
  attackers with authenticated access to execute arbitrary code on vulnerable
  installations.
 
  Impact Level: Application");
 
  script_tag(name:"affected", value:"Trend Micro Smart Protection Server
  (Standalone) 3.1 and 3.2");

  script_tag(name:"solution", value:"Upgrade to Trend Micro Smart Protection
  Server 3.2 B1085 or later.
  For updates refer to https://success.trendmicro.com/solution/1117933");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  ## Patch version is not available remotely
  script_xref(name : "URL" , value : "https://success.trendmicro.com/solution/1117933");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web Servers");
  script_dependencies("gb_trendmicro_smart_protection_server_detect.nasl");
  script_mandatory_keys("trendmicro/SPS/Installed");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

## Variable Initialization
tspsVer = "";
tspPort = "";

if(!tspPort = get_app_port(cpe:CPE)) exit(0);

## Get version
if(!tspsVer = get_app_version(cpe:CPE, port:tspPort)){
  exit(0);
}

##Check for vulnerable version
if(tspsVer == "3.1" || tspsVer == "3.2")
{
  report = report_fixed_ver(installed_version:tspsVer, fixed_version:"3.2 B1085");
  security_message(data:report, port:tspPort);
  exit(0);
}
