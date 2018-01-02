###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_acrobat_sandbox_bypass_vuln_aug14_win.nasl 8210 2017-12-21 10:26:31Z cfischer $
#
# Adobe Acrobat Sandbox Bypass Vulnerability - Aug14 (Windows)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:adobe:acrobat";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804814");
  script_version("$Revision: 8210 $");
  script_cve_id("CVE-2014-0546");
  script_bugtraq_id(69193);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-12-21 11:26:31 +0100 (Thu, 21 Dec 2017) $");
  script_tag(name:"creation_date", value:"2014-08-19 12:25:49 +0530 (Tue, 19 Aug 2014)");
  script_name("Adobe Acrobat Sandbox Bypass Vulnerability - Aug14 (Windows)");

  tag_summary =
"This host is installed with Adobe Acrobat and is prone to sandbox bypass
vulnerability.";

  tag_vuldetect =
"Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

  tag_insight =
"Flaw exists due to some unspecified error.";

 tag_impact =
"Successful exploitation will allow attacker to bypass sandbox restrictions
and execute native code in a privileged context.

Impact Level: System/Application";

  tag_affected =
"Adobe Acrobat X version 10.x before 10.1.11 and XI version 11.x before 11.0.08
on Windows.";

  tag_solution =
"Upgrade to version 10.1.11 or 11.0.08 or higher,
For updates refer to http://www.adobe.com/in/products/acrobat.html";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://helpx.adobe.com/security/products/reader/apsb14-19.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_win.nasl");
  script_mandatory_keys("Adobe/Acrobat/Win/Installed");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

## Variable Initialization
acrobatVer = "";

## Get version
if(!acrobatVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(acrobatVer && acrobatVer =~ "^(10|11)")
{
  ## Check Adobe Acrobat vulnerable version
  if((version_in_range(version:acrobatVer, test_version:"10.0", test_version2: "10.1.10"))||
     (version_in_range(version:acrobatVer, test_version:"11.0", test_version2: "11.0.07")))
  {
    security_message(0);
    exit(0);
  }
}
