###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_adobe_flash_player_mult_vuln_win_feb12.nasl 5958 2017-04-17 09:02:19Z teissa $
#
# Adobe Flash Player Multiple Vulnerabilities (Windows) - Feb12
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2012 SecPod, http://www.secpod.com
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

tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary
  code in the context of the affected application or cause a denial of
  service condition.
  Impact Level: Application.";
tag_affected = "Adobe Flash Player version before 10.3.183.15
  Adobe Flash Player version 11.x through 11.1.102.55 and prior on Windows";
tag_insight = "Flaws are due to
  - A memory corruption error in ActiveX control.
  - A type confusion memory corruption error.
  - An unspecified error related to MP4 parsing.
  - Many unspecified erros which allows to bypass certain security
    restrictions.
  - Improper validation of user supplied input which allows attackers
    to execute arbitrary HTML and script code in a user's browser session";
tag_solution = "Upgrade to Adobe Flash Player version 11.1.102.62 or later,
  For updates refer to http://www.adobe.com/downloads/";
tag_summary = "This host is installed with Adobe Flash Player and is prone to
  multiple vulnerabilities.";

if(description)
{
  script_id(802803);
  script_version("$Revision: 5958 $");
  script_cve_id("CVE-2012-0751", "CVE-2012-0752", "CVE-2012-0753", "CVE-2012-0754",
                "CVE-2012-0757", "CVE-2012-0756", "CVE-2012-0767");
  script_bugtraq_id(52037, 52032, 52033, 52034, 51999, 52036, 52040);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-04-17 11:02:19 +0200 (Mon, 17 Apr 2017) $");
  script_tag(name:"creation_date", value:"2012-02-22 11:17:41 +0530 (Wed, 22 Feb 2012)");
  script_name("Adobe Flash Player Multiple Vulnerabilities (Windows) - Feb12");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/48033");
  script_xref(name : "URL" , value : "http://securitytracker.com/id/1026694");
  script_xref(name : "URL" , value : "http://www.securelist.com/en/advisories/48033");
  script_xref(name : "URL" , value : "http://www.adobe.com/support/security/bulletins/apsb12-03.html");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 SecPod");
  script_family("General");
  script_dependencies("gb_adobe_flash_player_detect_win.nasl");
  script_require_keys("AdobeFlashPlayer/Win/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}

include("version_func.inc");

# Variable Initialization
flashVer = NULL;

#Get Adobe Flash Player Version
flashVer = get_kb_item("AdobeFlashPlayer/Win/Ver");
if(isnull(flashVer)){
  exit(0);
}

## Check for Adobe Flash Player versions 11.1.102.55 and prior
if(version_is_less(version:flashVer, test_version:"10.3.183.15")||
   version_in_range(version:flashVer, test_version:"11.0", test_version2:"11.1.102.55")){
  security_message(0);
}
