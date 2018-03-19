###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hp_support_assistant_auth_bypass_vuln_win.nasl 9121 2018-03-17 13:28:53Z cfischer $
#
# HP Support Assistant Authentication Bypass Vulnerability (Windows)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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
##########################################################################

CPE = "cpe:/a:hp:support_assistant";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807805");
  script_version("$Revision: 9121 $");
  script_cve_id("CVE-2016-2245");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-03-17 14:28:53 +0100 (Sat, 17 Mar 2018) $");
  script_tag(name:"creation_date", value:"2016-04-20 17:05:22 +0530 (Wed, 20 Apr 2016)");
  script_name("HP Support Assistant Authentication Bypass Vulnerability (Windows)");

  script_tag(name:"summary" , value:"This host is installed with HP Support
  Assistant and is prone to authentication bypass vulnerability.");

  script_tag(name:"vuldetect" , value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name:"insight" , value:"The flaw exists due to some unspecified
  error.");

  script_tag(name:"impact" , value:"Successful exploitation will allow attacker
  to bypass authentication and get administrative privileges.

  Impact Level: Application");

  script_tag(name:"affected" , value:"HP Support Assistant version 8.1.40.3 and
  prior on Windows.");

  script_tag(name:"solution" , value:"Upgrade to HP Support Assistant version
  8.1.52.1 or later. For updates refer to,
  http://www8.hp.com/in/en/campaigns/hpsupportassistant/hpsupport.html");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name : "URL" , value : "https://h20565.www2.hp.com/hpsc/doc/public/display?docId=emr_na-c05031674");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_hp_support_assistant_detect.nasl");
  script_mandatory_keys("HP/Support/Assistant/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

## Variable Initialization
hpVer = "";

## Get version
if(!hpVer = get_app_version(cpe:CPE)){
  exit(0);
}

## Check for HP Support Assistant Version less than 8.1.52.1
if(version_is_less(version:hpVer, test_version:"8.1.52.1"))
{
  report = report_fixed_ver(installed_version:hpVer, fixed_version:"8.1.52.1");
  security_message(data:report);
  exit(0);
}
