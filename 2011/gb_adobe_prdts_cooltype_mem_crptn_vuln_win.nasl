###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_prdts_cooltype_mem_crptn_vuln_win.nasl 8210 2017-12-21 10:26:31Z cfischer $
#
# Adobe Reader and Acrobat 'CoolType.dll' Memory Corruption Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.801933");
  script_version("$Revision: 8210 $");
  script_cve_id("CVE-2011-0610");
  script_bugtraq_id(47531);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-12-21 11:26:31 +0100 (Thu, 21 Dec 2017) $");
  script_tag(name:"creation_date", value:"2011-05-16 15:25:30 +0200 (Mon, 16 May 2011)");
  script_name("Adobe Reader and Acrobat 'CoolType.dll' Memory Corruption Vulnerability");

  tag_summary = "This host is installed with Adobe Reader/Acrobat and is prone to memory
corruption and reemote code execution vulnerability";

  tag_vuldetect = "Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

  tag_insight = "This issue is caused by a memory corruption error in the 'CoolType' library
when processing the malformed Flash content within a PDF document.";

  tag_impact = "Successful exploitation will let attackers to crash an affected application
or compromise a vulnerable system by tricking a user into opening a specially
crafted PDF file.

Impact Level:Application";

  tag_affected = "Adobe Reader version prior to 9.4.4 and 10.x to 10.0.1

Adobe Acrobat version prior to 9.4.4 and 10.x to 10.0.2 on windows";

  tag_solution = "Upgrade to Adobe Reader version 9.4.4 or Acrobat 9.4.4 or 10.0.3
For updates refer to http://www.adobe.com

  *****
  NOTE : No fix available for Adobe Reader X (10.x), vendors are planning to
         address this issue in next quarterly security update for Adobe Reader.
  *****";

  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2011/0923");
  script_xref(name : "URL" , value : "http://www.adobe.com/support/security/bulletins/apsb11-08.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_win.nasl");
  script_mandatory_keys("Adobe/Air_or_Flash_or_Reader_or_Acrobat/Win/Installed");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

CPE = "cpe:/a:adobe:acrobat_reader";
if(readerVer = get_app_version(cpe:CPE, nofork:TRUE))
{
  # Check for Adobe Reader version < 9.4.4 and 10.x to 10.0.1
  if(version_is_less(version:readerVer, test_version:"9.4.4") ||
    version_in_range(version:readerVer, test_version:"10.0", test_version2:"10.0.1"))
  {
    security_message(0);
  }
}

CPE = "cpe:/a:adobe:acrobat";
if(acrobatVer = get_app_version(cpe:CPE))
{
  # Check for Adobe Acrobat version < 9.4.4 and 10.x to 10.0.2
  if(version_is_less(version:acrobatVer, test_version:"9.4.4") ||
     version_in_range(version:acrobatVer, test_version:"10.0", test_version2:"10.0.2")){
    security_message(0);
    exit(0);
  }
}
