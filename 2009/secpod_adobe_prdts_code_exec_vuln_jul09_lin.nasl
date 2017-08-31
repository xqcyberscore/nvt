###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_adobe_prdts_code_exec_vuln_jul09_lin.nasl 6476 2017-06-29 07:32:00Z cfischer $
#
# Adobe Products '.pdf' and '.swf' Code Execution Vulnerability - July09 (Linux)
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (C) 2009 SecPod, http://www.secpod.com
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

SCRIPT_OID = "1.3.6.1.4.1.25623.1.0.900807";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 6476 $");
  script_cve_id("CVE-2009-1862");
  script_bugtraq_id(35759);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-06-29 09:32:00 +0200 (Thu, 29 Jun 2017) $");
  script_tag(name:"creation_date", value:"2009-07-29 08:47:44 +0200 (Wed, 29 Jul 2009)");
  script_name("Adobe Products '.pdf' and '.swf' Code Execution Vulnerability - July09 (Linux)");

  tag_summary =
"This host is installed with Adobe products and is prone to remote code
execution vulnerability.";

  tag_vuldetect =
"Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

  tag_insight =
"- An unspecified error exists in Adobe Flash Player which can be exploited via
a specially crafted flash application in a '.pdf' file.
- Error occurs in 'authplay.dll' in Adobe Reader/Acrobat whlie processing '.swf'
content and can be exploited to execute arbitrary code.";

  tag_impact =
"Successful exploitation will allow remote attackers to cause code execution
on the affected application.

Impact Level: Application";

  tag_affected =
"Adobe Reader/Acrobat version 9.x to 9.1.2
Adobe Flash Player version 9.x to 9.0.159.0 and 10.x to 10.0.22.87 on Linux.";

  tag_solution =
"Upgrade to Adobe Reader/Acrobat version 9.1.3 or later.
Upgrade to Adobe Flash Player version 9.0.246.0 or 10.0.32.18 or later.
For updates refer to http://www.adobe.com/";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/35948/");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/35949/");
  script_xref(name : "URL" , value : "http://www.kb.cert.org/vuls/id/259425");
  script_xref(name : "URL" , value : "http://www.adobe.com/support/security/advisories/apsa09-03.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("General");
  script_dependencies("gb_adobe_flash_player_detect_lin.nasl", "gb_adobe_prdts_detect_lin.nasl");
  script_mandatory_keys("Adobe/Air_or_Flash_or_Reader/Linux/Installed");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

## Variable Initialization
readerVer = "";
playerVer = "";

# Check for Adobe Flash Player version 9.x to 9.0.159.0 or 10.x to 10.0.22.87
playerVer = get_kb_item("AdobeFlashPlayer/Linux/Ver");

if(playerVer != NULL)
{
  if(version_in_range(version:playerVer, test_version:"9.0", test_version2:"9.0.159.0") ||
     version_in_range(version:playerVer, test_version:"10.0", test_version2:"10.0.22.87"))
  {
    security_message(0);
  }
}

##CPE for adobe reader
CPE = "cpe:/a:adobe:acrobat_reader";

## Get version
if(readerVer = get_app_version(cpe:CPE, nvt:SCRIPT_OID))
{
  # Check for Adobe Reader version 9.x to 9.1.2
  if(readerVer =~ "^9")
  {
    if(version_in_range(version:readerVer, test_version:"9.0", test_version2:"9.1.2"))
    {
      security_message(0);
      exit(0);
    }
  }
}
