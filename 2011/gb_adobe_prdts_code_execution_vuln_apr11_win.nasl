###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_prdts_code_execution_vuln_apr11_win.nasl 8210 2017-12-21 10:26:31Z cfischer $
#
# Adobe Products Arbitrary Code Execution Vulnerability (Windows)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801921");
  script_version("$Revision: 8210 $");
  script_cve_id("CVE-2011-0611");
  script_bugtraq_id(47314);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-12-21 11:26:31 +0100 (Thu, 21 Dec 2017) $");
  script_tag(name:"creation_date", value:"2011-04-22 16:38:12 +0200 (Fri, 22 Apr 2011)");
  script_name("Adobe Products Arbitrary Code Execution Vulnerability (Windows)");

  tag_summary = "This host has Adobe Acrobat or Adobe Reader or Adobe flash Player installed
and is prone to code execution vulnerability.";

  tag_vuldetect = "Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

  tag_insight = "The flaw is due to an error in handling 'SWF' file in adobe flash player and
'Authplay.dll' in Adobe acrobat/reader. which allows attackers to execute
arbitrary code or cause a denial of service via crafted flash content.";

  tag_impact = "Successful exploitation will let attackers to corrupt memory and execute
arbitrary code on the system with elevated privileges.

Impact Level: System/Application";

  tag_affected = "Adobe Flash Player version 10.2.153.1 and prior on Windows.

Adobe Reader/Acrobat version 9.x to 9.4.3 and 10.x to 10.0.2 on windows.";

  tag_solution = "Upgrade adobe flash player to version 10.2.159.1 or later,
Update Adobe Reader/Acrobat to version 9.4.4 or 10.0.3 or later,
For updates refer to http://www.adobe.com";

  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "https://www.kb.cert.org/vuls/id/230057");
  script_xref(name : "URL" , value : "http://www.adobe.com/support/security/advisories/apsa11-02.html");
  script_xref(name : "URL" , value : "http://blogs.adobe.com/psirt/2011/04/security-advisory-for-adobe-flash-player-adobe-reader-and-acrobat-apsa11-02.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_win.nasl", "gb_adobe_flash_player_detect_win.nasl");
  script_mandatory_keys("Adobe/Air_or_Flash_or_Reader_or_Acrobat/Win/Installed");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

CPE = "cpe:/a:adobe:acrobat_reader";
if(readerVer = get_app_version(cpe:CPE, nofork:TRUE))
{
  if(readerVer =~ "^(9|10)")
  {
    if(version_in_range(version:readerVer, test_version:"9.0", test_version2:"9.4.3") ||
       version_in_range(version:readerVer, test_version:"10.0", test_version2:"10.0.2")){
      security_message(0);
    }
  }
}

CPE = "cpe:/a:adobe:acrobat";
if(acrobatVer = get_app_version(cpe:CPE, nofork:TRUE))
{
  if(version_in_range(version:acrobatVer, test_version:"9.0", test_version2:"9.4.3") ||
     version_in_range(version:acrobatVer, test_version:"10.0", test_version2:"10.0.2"))
  {
    security_message(0);
    exit(0);
  }
}

CPE = "cpe:/a:adobe:flash_player";
if(flashVer = get_app_version(cpe:CPE))
{
  # Check for Adobe Flash Player version <= 10.2.153.1
  if(version_is_less_equal(version:flashVer, test_version:"10.2.153.1")){
    security_message(0);
  }
}
