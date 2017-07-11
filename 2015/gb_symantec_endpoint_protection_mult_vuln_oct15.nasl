###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_symantec_endpoint_protection_mult_vuln_oct15.nasl 6243 2017-05-30 09:04:14Z teissa $
#
# Symantec Endpoint Protection Multiple Vulnerabilities Oct15
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
CPE = "cpe:/a:symantec:endpoint_protection";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805982");
  script_version("$Revision: 6243 $");
  script_cve_id("CVE-2014-9229", "CVE-2014-9228", "CVE-2014-9227");
  script_bugtraq_id(75204, 75202, 75203);
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-05-30 11:04:14 +0200 (Tue, 30 May 2017) $");
  script_tag(name:"creation_date", value:"2015-10-09 11:10:42 +0530 (Fri, 09 Oct 2015)");
  script_name("Symantec Endpoint Protection Multiple Vulnerabilities Oct15");

  script_tag(name: "summary" , value: "This host is installed with Symantec
  Endpoint Protection and is prone to multiple vulnerabilities.");

  script_tag(name: "vuldetect" , value: "Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value: "Multiple flaws exists as,
  - An error in the 'sysplant.sys' in the Manager component.
  - An error in interface PHP scripts in the Manager component in Symantec Endpoint
    Protection.
  - Untrusted search path errors in the Manager component in Symantec Endpoint
    Protection.");

  script_tag(name: "impact" , value: "Successful exploitation will allow attacker
  to gain elevated privileges, execute arbitrary SQL commands, cause a denial of
  service condition.

  Impact Level: Application.");

  script_tag(name: "affected" , value:"Symantec Endpoint Protection (SEP) before
  version 12.1 RU6");

  script_tag(name: "solution" , value:"Update to Symantec Endpoint Protection (SEP)
  version 12.1 RU6 or later. For updates refer to
  http://www.symantec.com/en/in/endpoint-protection");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");

  script_xref(name: "URL" , value : "http://www.securitytracker.com/id/1032616");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("secpod_symantec_prdts_detect.nasl");
  script_mandatory_keys("Symantec/Endpoint/Protection");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

## Variable Initialization
sepVer= "";

## Get version
if(!sepVer = get_app_version(cpe:CPE)){
  exit(0);
}

## Get SEP Product type from KB to check for SEP SmallBusiness
sepType = get_kb_item("Symantec/SEP/SmallBusiness");

## Check for Symantec Endpoint Protection versions
## https://en.wikipedia.org/wiki/Symantec_Endpoint_Protection#Version_history
## Check for vulnerable version < 12.1.6 = 12.1 RU6 (12.1.6168.6000)
if(isnull(sepType) &&
   version_in_range(version:sepVer, test_version:"12.1", test_version2:"12.1.6168.5999"))
{
  report = 'Installed version: ' + sepVer + '\n' +
           'Fixed version:     ' + '12.1 RU6' + '\n';
  security_message(data:report);
  exit(0);
}
