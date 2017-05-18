##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_avast_free_antivirus_dll_loading_local_code_injection_vuln.nasl 6036 2017-04-27 06:04:46Z antu123 $
#
# Avast Free Antivirus DoubleAgent Attack Local Code Injection Vulnerability
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
##############################################################################

CPE = "cpe:/a:avast:avast_antivirus";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810902");
  script_version("$Revision: 6036 $");
  script_cve_id("CVE-2017-5567");
  script_bugtraq_id(97017);
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-04-27 08:04:46 +0200 (Thu, 27 Apr 2017) $");
  script_tag(name:"creation_date", value:"2017-04-05 10:13:58 +0530 (Wed, 05 Apr 2017)");
  script_name("Avast Free Antivirus DoubleAgent Attack Local Code Injection Vulnerability");

  script_tag(name:"summary", value:"This host is installed with Avast Free Antivirus
  and is prone to local code injection vulnerability.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name:"insight", value:"The flaw exists due to the product do not
  use the Protected Processes feature, and therefore an attacker can enter an 
  arbitrary Application Verifier Provider DLL under Image File Execution Options 
  in the registry; the self-protection mechanism is intended to block all local 
  processes (regardless of privileges) from modifying Image File Execution Options
  for this product; and this mechanism can be bypassed by an attacker who 
  temporarily renames Image File Execution Options during the attack.");

  script_tag(name:"impact", value:"Successful exploitation will allow local
  attacker to execute arbitrary code in the context of the system running the
  affected application; this can also result in the attacker gaining complete
  control of the affected application.

  Impact Level: System/Application");

  script_tag(name:"affected", value:"Avast Free Antivirus version 12.3 and prior.");

  script_tag(name:"solution", value:"No solution or patch is available as
  of 5th April, 2017. Information regarding this issue will be updated
  once the solution details are available. 
  For updates refer to https://www.avast.com");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name : "URL" , value : "http://feeds.security-database.com/~r/Last100Alerts/~3/M6mwzAVFo-U/detail.php");
  script_xref(name : "URL" , value : "https://www.engadget.com/2017/03/21/doubleagent-attack-anti-virus-hijack-your-pc");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_avast_av_detect_win.nasl");
  script_mandatory_keys("Avast!/AV/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

## Variable Initialization
avastVer = "";

## Get version
if(!avastVer = get_app_version(cpe:CPE)){
  exit(0);
}

## Grep for vulnerable version
if(version_is_less_equal(version:avastVer, test_version:"12.3"))
{
  report = report_fixed_ver(installed_version:avastVer, fixed_version:"NoneAvailable");
  security_message(data:report);
  exit(0);
}
