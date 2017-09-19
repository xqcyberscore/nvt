##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ipass_open_mobile_remote_code_exec_vuln_win.nasl 7174 2017-09-18 11:48:08Z asteins $
#
# iPass Open Mobile Remote Code Execution Vulnerability (Windows)
#
# Authors:
# Tushar Khelge <ktushar@secpod.com>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:ipass:ipass_open_mobile";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808732");
  script_version("$Revision: 7174 $");
  script_cve_id("CVE-2015-0925");
  script_bugtraq_id(72265);
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-09-18 13:48:08 +0200 (Mon, 18 Sep 2017) $");
  script_tag(name:"creation_date", value:"2016-08-03 16:39:37 +0530 (Wed, 03 Aug 2016)");
  script_name("iPass Open Mobile Remote Code Execution Vulnerability (Windows)");

  script_tag(name: "summary" , value:"This host is installed with iPass Open
  Mobile and is prone to remote code execution vulnerability.");

  script_tag(name: "vuldetect" , value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value:"The flaw exists due to a dll pathname in a
  crafted unicode string improperly handled by a subprocess reached through a
  named pipe.");

  script_tag(name: "impact" , value:"Successful exploitation will allow remote
  authenticated users to execute arbitrary code.

  Impact Level: System/Application");

  script_tag(name: "affected" , value:"iPass Open Mobile prior to 2.4.5
  on Windows.");

  script_tag(name: "solution" , value:"Upgrade to iPass Open Mobile 2.4.5
  For updates refer to http://www.ipass.com/");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name : "URL" , value : "http://www.kb.cert.org/vuls/id/110652");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_ipass_open_mobile_detect_win.nasl");
  script_mandatory_keys("IPass/OpenMobile/Win/Ver");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

## Variable Initialization
ipassVer = "";

## Get version
if(!ipassVer = get_app_version(cpe:CPE)){
  exit(0);
}

##Check For Version
if(version_is_less(version:ipassVer, test_version:"2.4.5"))
{
  report = report_fixed_ver(installed_version:ipassVer, fixed_version:"2.4.5");
  security_message(data:report);
  exit(0);
}
