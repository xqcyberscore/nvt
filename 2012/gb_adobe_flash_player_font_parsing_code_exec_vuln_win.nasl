###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_flash_player_font_parsing_code_exec_vuln_win.nasl 3563 2016-06-20 14:55:04Z benallard $
#
# Adobe Flash Player Font Parsing Code Execution Vulnerability - (Windows)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation will let attackers to execute arbitrary code or
  cause the application to crash and take control of the affected system.
  Impact Level: System/Application";
tag_affected = "Adobe Flash Player version prior to 11.3.300.271 on Windows";
tag_insight = "An unspecified error occurs when handling SWF content in a word document.
  This may allow a context-dependent attacker to execute arbitrary code.";
tag_solution = "Upgrade to Adobe Flash Player version 11.3.300.271 or later,
  For details refer, http://www.adobe.com/downloads/";
tag_summary = "This host is installed with Adobe Flash Player and is prone to
  unspecified code execution vulnerability.";

if(description)
{
  script_id(802940);
  script_version("$Revision: 3563 $");
  script_cve_id("CVE-2012-1535");
  script_bugtraq_id(55009);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2016-06-20 16:55:04 +0200 (Mon, 20 Jun 2016) $");
  script_tag(name:"creation_date", value:"2012-08-20 13:00:42 +0530 (Mon, 20 Aug 2012)");
  script_name("Adobe Flash Player Font Parsing Code Execution Vulnerability - (Windows)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/50285/");
  script_xref(name : "URL" , value : "http://www.adobe.com/support/security/bulletins/apsb12-18.html");

  script_summary("Check for the version of Adobe Flash Player on Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_flash_player_detect_win.nasl");
  script_require_keys("AdobeFlashPlayer/Win/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("version_func.inc");

## Variable Initialization
flashVer = "";

## Get the version
flashVer = get_kb_item("AdobeFlashPlayer/Win/Ver");
if(!flashVer){
  exit(0);
}

## Check for Adobe Flash Player versions prior to 11.3.300.271
if(version_is_less(version:flashVer, test_version:"11.3.300.271")){
  security_message(0);
}
