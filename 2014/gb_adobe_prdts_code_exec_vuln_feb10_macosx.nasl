###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_prdts_code_exec_vuln_feb10_macosx.nasl 8210 2017-12-21 10:26:31Z cfischer $
#
# Adobe Acrobat and Reader PDF Handling Code Execution Vulnerability (Mac OS X)
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804267");
  script_version("$Revision: 8210 $");
  script_cve_id("CVE-2010-0188", "CVE-2010-0186");
  script_bugtraq_id(38195, 38198);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-12-21 11:26:31 +0100 (Thu, 21 Dec 2017) $");
  script_tag(name:"creation_date", value:"2014-04-16 15:25:45 +0530 (Wed, 16 Apr 2014)");
  script_name("Adobe Acrobat and Reader PDF Handling Code Execution Vulnerability (Mac OS X)");

  tag_summary = "This host is installed with Adobe Reader/Acrobat and is prone to remote code
execution vulnerability.";

  tag_vuldetect = "Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

  tag_insight = "Flaw is caused by a memory corruption error in the 'authplay.dll' module
when processing malformed Flash data within a PDF document and some unspecified
error.";

  tag_impact = "Successful exploitation will let attackers to execute arbitrary code by tricking
a user into opening a PDF file embedding a malicious Flash animation and bypass
intended sandbox restrictions allowing cross-domain requests.

Impact Level: System/Application";

  tag_affected = "Adobe Reader version 8.x before 8.2.1 and 9.x before 9.3.1 on Mac OS X.

  Adobe Acrobat version 8.x before 8.2.1 and 9.x before 9.3.1 on Mac OS X";

 tag_solution = "Upgrade to Adobe Reader/Acrobat version 9.3.1 or 8.2.1 or later. For updates
refer to http://www.adobe.com";

  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/56297");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/0399");
  script_xref(name : "URL" , value : "http://securitytracker.com/alerts/2010/Feb/1023601.html");
  script_xref(name : "URL" , value : "http://www.adobe.com/support/security/bulletins/apsb10-07.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_macosx.nasl");
  script_mandatory_keys("Adobe/Air_or_Flash_or_Reader/MacOSX/Installed");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

## Variable Initialization
readerVer = "";

##CPE for Adobe Reader
CPE = "cpe:/a:adobe:acrobat_reader";

## Get version
if(readerVer = get_app_version(cpe:CPE))
{
  # Check for Adobe Reader version 9.x to 9.3.0, and  < 8.2.1
  if(version_is_less(version:readerVer, test_version:"8.2.1") ||
     version_in_range(version:readerVer, test_version:"9.0", test_version2:"9.3.0"))
  {
    security_message(0);
  }
}

##CPE for Adobe Acrobat
CPE = "cpe:/a:adobe:acrobat";

if(acrobatVer = get_app_version(cpe:CPE))
{
  # Check for Adobe Acrobat version 9.x to 9.3.0, and  < 8.2.1
  if(version_is_less(version:acrobatVer, test_version:"8.2.1") ||
     version_in_range(version:acrobatVer, test_version:"9.0", test_version2:"9.3.0")){
    security_message(0);
    exit(0);
  }
}
