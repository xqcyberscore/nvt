###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_prdts_code_exec_vuln_lin_jun10.nasl 8287 2018-01-04 07:28:11Z teissa $
#
# Adobe Products Remote Code Execution Vulnerability - jun10 (Linux)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_solution = "For Adobe Flash Player,
Update to Adobe Flash Player 10.1.53.64 or 9.0.277.0 or later
http://www.adobe.com/support/flashplayer/downloads.html

For Adobe Reader
Vendor has released a patch for the issue, refer below link,
http://www.adobe.com/support/security/advisories/apsa10-01.html
For updates refer to http://www.adobe.com/";

tag_impact = "Successful exploitation will allow remote attackers to execute
arbitrary code by tricking a user into opening a specially crafted PDF file.

Impact Level: System/Application";

tag_affected = "Adobe Reader version 9.x to 9.3.2
Adobe Flash Player version 9.0.x to 9.0.262 and 10.x through 10.0.45.2";

tag_insight = "The flaw is due to a memory corruption error in the
'libauthplay.so.0.0.0' library and 'SWF' file when processing ActionScript
Virtual Machine 2 (AVM2) 'newfunction' instructions within Flash content in a
PDF document.";

tag_summary = "This host is installed with Adobe products and is prone to
remote code execution vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801361");
  script_version("$Revision: 8287 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-04 08:28:11 +0100 (Thu, 04 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-06-15 06:05:27 +0200 (Tue, 15 Jun 2010)");
  script_cve_id("CVE-2010-1297");
  script_bugtraq_id(40586);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Adobe Products Remote Code Execution Vulnerability - jun10 (Linux)");

  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/1349");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/1348");
  script_xref(name : "URL" , value : "http://www.adobe.com/support/security/advisories/apsa10-01.html");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_prdts_detect_lin.nasl", "gb_adobe_flash_player_detect_lin.nasl");
  script_mandatory_keys("Adobe/Air_or_Flash_or_Reader/Linux/Installed");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "solution" , value : tag_solution);
  exit(0);
}


include("version_func.inc");

# Check for Adobe Flash Player
pVer = get_kb_item("AdobeFlashPlayer/Linux/Ver");
if(pVer != NULL)
{
  #  Adobe Flash Player version 9.0.0 to 9.0.262 and 10.x to 10.0.45.2
  if(version_in_range(version:pVer, test_version:"9.0.0", test_version2:"9.0.262") ||
  version_in_range(version:pVer, test_version:"10.0", test_version2:"10.0.45.2"))
  {
    security_message(0);
    exit(0);
  }
}

# Adobe Reader
arVer = get_kb_item("Adobe/Reader/Linux/Version");
if(arVer != NULL)
{
  # Grep for Adobe Reader version 9.0 to 9.3.2
  if(version_in_range(version:arVer, test_version:"9.0", test_version2:"9.3.2")){
    security_message(0);
  }
}
