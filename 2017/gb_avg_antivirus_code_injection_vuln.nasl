##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_avg_antivirus_code_injection_vuln.nasl 5941 2017-04-12 12:01:06Z antu123 $
#
# AVG Antivirus Code Injection Vulnerability
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

CPE = "cpe:/a:avg:avg_anti-virus";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810835");
  script_version("$Revision: 5941 $");
  script_cve_id("CVE-2017-5566");
  script_bugtraq_id(97022);
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-04-12 14:01:06 +0200 (Wed, 12 Apr 2017) $");
  script_tag(name:"creation_date", value:"2017-04-04 17:45:27 +0530 (Tue, 04 Apr 2017)");
  script_name("AVG Antivirus Code Injection Vulnerability");

  script_tag(name: "summary" , value:"The host is installed with AVG Antivirus
  and is prone to code injection vulnerability.");

  script_tag(name: "vuldetect" , value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value:"The flaw exists due to,
  - No use of Protected Processes feature, and therefore an attacker can enter an
    arbitrary Application Verifier Provider DLL under Image File Execution Options
    in the registry.
  - The self-protection mechanism is intended to block all local processes
    (regardless of privileges) from modifying Image File Execution Options for these
    products.");

  script_tag(name: "impact" , value:"Successful exploitation of these
  vulnerabilities will allow a local attacker to bypass a self-protection
  mechanism, inject arbitrary code, and take full control of any AVG process
  via a 'DoubleAgent' attack.

  Impact Level: Application");

  script_tag(name: "affected" , value:"AVG Antivirus 17.1 and earlier on Windows");

  script_tag(name: "solution", value:"Apply the mitigation from below link,
  https://cybellum.com/doubleagentzero-day-code-injection-and-persistence-technique");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name : "URL" , value : "https://cybellum.com/doubleagentzero-day-code-injection-and-persistence-technique");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_avg_detect_win.nasl");
  script_mandatory_keys("AVG/AV/Win/Ver");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

## Variable Initialization
avg_anti_Ver = "";

## Get version
if(!avg_anti_Ver = get_app_version(cpe:CPE)){
  exit(0);
}

## Grep for vulnerable version
if(version_is_less(version:avg_anti_Ver, test_version:"17.1"))
{
  report = report_fixed_ver(installed_version:avg_anti_Ver, fixed_version:"Mitigation");
  security_message(data:report);
  exit(0);
}
