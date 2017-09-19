###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_foxit_reader_arbitrary_code_vuln_lin.nasl 7174 2017-09-18 11:48:08Z asteins $
#
# Foxit Reader Arbitrary Code Execution Vulnerability (Linux)
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
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

CPE = "cpe:/a:foxitsoftware:reader";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809333");
  script_version("$Revision: 7174 $");
  script_cve_id("CVE-2016-8856");
  script_bugtraq_id(93608); 
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-09-18 13:48:08 +0200 (Mon, 18 Sep 2017) $");
  script_tag(name:"creation_date", value:"2016-11-08 17:31:49 +0530 (Tue, 08 Nov 2016)");
  script_name("Foxit Reader Arbitrary Code Execution Vulnerability (Linux)");

  script_tag(name: "summary" , value:"The host is installed with Foxit Reader
  and is prone to arbitrary code execution vulnerability.");

  script_tag(name: "vuldetect" , value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value:"The flaw exists due to Foxit Reader's core
  files are world-writable by default."); 

  script_tag(name: "impact" , value:"Successful exploitation will allow remote
  attackers to overwrite core files with backdoor code, which when executed by 
  privileged user would result in Privilege Escalation, Code Execution, or both.

  Impact Level: System/Application");

  script_tag(name: "affected" , value:"Foxit Reader version 2.1.0.0805 and 
  earlier");

  script_tag(name: "solution" , value:"Upgrade to Foxit Reader version
  2.2.1025 or later, For updates refer to http://www.foxitsoftware.com");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name : "URL" , value:"https://www.foxitsoftware.com/support/security-bulletins.php");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_foxit_reader_detect_lin.nasl");
  script_mandatory_keys("Foxit/Reader/Linux/Ver");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

## Variable Initialization
foxitVer = "";

## Get version
if(!foxitVer = get_app_version(cpe:CPE)){
  exit(0);
}

## Grep for vulnerable version
## 2.2.1025 is the latest version available
if(version_is_less_equal(version:foxitVer, test_version:"2.1.0.0805"))
{
  report = report_fixed_ver(installed_version:foxitVer, fixed_version:"2.2.1025");
  security_message(data:report);
  exit(0);
}
