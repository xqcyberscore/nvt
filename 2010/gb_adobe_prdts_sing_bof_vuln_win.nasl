###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_prdts_sing_bof_vuln_win.nasl 6475 2017-06-29 06:35:11Z cfischer $
#
# Adobe Acrobat and Reader SING 'uniqueName' Buffer Overflow Vulnerability (Windows)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.801515";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 6475 $");
  script_cve_id("CVE-2010-2883");
  script_bugtraq_id(43057);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-06-29 08:35:11 +0200 (Thu, 29 Jun 2017) $");
  script_tag(name:"creation_date", value:"2010-09-15 08:47:45 +0200 (Wed, 15 Sep 2010)");
  script_name("Adobe Acrobat and Reader SING 'uniqueName' Buffer Overflow Vulnerability (Windows)");

  tag_summary =
"This host is installed with Adobe Reader/Acrobat and is prone to buffer
overflow vulnerability";

  tag_vuldetect =
"Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

 tag_insight =
"The flaw is due to a boundary error within 'CoolType.dll' when processing the
'uniqueName' entry of SING tables in fonts.";

  tag_impact =
"Successful exploitation will let attackers to crash an affected application
or execute arbitrary code by tricking a user into opening a specially crafted
PDF document.

Impact Level: Application";

  tag_affected =
"Adobe Reader version 9.3.4 and prior.
Adobe Acrobat version 9.3.4 and prior on windows.";

  tag_solution =
"Upgrade to Adobe Reader/Adobe Acrobat version 9.4 or later.
For updates refer http://www.adobe.com/downloads/";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/41340");
  script_xref(name : "URL" , value : "http://www.adobe.com/support/security/advisories/apsa10-02.html");
  script_xref(name : "URL" , value : "http://blog.metasploit.com/2010/09/return-of-unpublished-adobe.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("secpod_adobe_prdts_detect_win.nasl");
  script_mandatory_keys("Adobe/Air_or_Flash_or_Reader_or_Acrobat/Win/Installed");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

## Variable Initialization
readerVer = "";
acrobatVer = "";

##CPE for adobe reader
CPE = "cpe:/a:adobe:acrobat_reader";

## Get Reader Version
if(readerVer = get_app_version(cpe:CPE, nvt:SCRIPT_OID))
{
  # Check for Adobe Reader version <= 9.3.4
  if(version_is_less(version:readerVer, test_version:"9.3.4"))
  {
    security_message(0);
  }
}

acrobatVer = get_kb_item("Adobe/Acrobat/Win/Ver");
if(!acrobatVer){
  exit(0);
}

# Check for Adobe Acrobat version <= 9.3.4
if(version_is_less_equal(version:acrobatVer, test_version:"9.3.4")){
  security_message(0);
  exit(0);
}
