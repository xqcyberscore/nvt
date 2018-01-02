###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_prdts_arbitrary_code_exec_vuln_nov10_lin.nasl 8258 2017-12-29 07:28:57Z teissa $
#
# Adobe Products Arbitrary Code Execution Vulnerability (Linux)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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

tag_solution = "Adobe Flash Player:
Upgrade to Adobe Flash Player version 10.1.102.64 or later
For details refer, http://www.adobe.com/downloads/

Adobe Reader/Acrobat:
Upgrade to Adobe Reader/Acrobat version 9.4.1 or later,
For updates refer to http://www.adobe.com/downloads/";

tag_impact = "Successful exploitation will let attackers to execute arbitrary
code in the context of the user running the affected application.

Impact Level: Application/System";

tag_affected = "Adobe Reader/Acrobat version 9.x to 9.4 on Linux
Adobe Flash Player version 10.1.85.3 and prior on Linux";

tag_insight = "The flaw is caused by an unspecified error which can be exploited
to execute arbitrary code.";

tag_summary = "This host has Adobe Acrobat or Adobe Reader or Adobe flash Player
installed, and is prone to arbitrary code execution vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801478");
  script_version("$Revision: 8258 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-29 08:28:57 +0100 (Fri, 29 Dec 2017) $");
  script_tag(name:"creation_date", value:"2010-11-10 14:58:25 +0100 (Wed, 10 Nov 2010)");
  script_cve_id("CVE-2010-3654");
  script_bugtraq_id(44504);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Adobe Products Content Code Execution Vulnerability (Linux)");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/41917");
  script_xref(name : "URL" , value : "http://www.kb.cert.org/vuls/id/298081");
  script_xref(name : "URL" , value : "http://contagiodump.blogspot.com/2010/10/potential-new-adobe-flash-player-zero.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_prdts_detect_lin.nasl", "gb_adobe_flash_player_detect_lin.nasl");
  script_mandatory_keys("Adobe/Air_or_Flash_or_Reader/Linux/Installed");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("version_func.inc");

# Check for Adobe Reader version <= 9.4
readerVer = get_kb_item("Adobe/Reader/Linux/Version");
if(readerVer)
{
  if(version_in_range(version:readerVer, test_version:"9.0.0", test_version2:"9.4"))
  {
    security_message(0);
    exit(0);
  }
}

# Check for Adobe Flash Player version <= 10.1.85.3
flashVer = get_kb_item("AdobeFlashPlayer/Linux/Ver");
flashVer = ereg_replace(pattern:",", string:flashVer, replace: ".");
if(flashVer)
{
  if(version_is_less_equal(version:flashVer, test_version:"10.1.85.3")){
    security_message(0);
  }
}
