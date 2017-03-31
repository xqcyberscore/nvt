###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_prdts_xss_vuln_win_jun11.nasl 5424 2017-02-25 16:52:36Z teissa $
#
# Adobe Products Unspecified Cross-Site Scripting Vulnerability June-2011 (Windows)
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.802206";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 5424 $");
  script_cve_id("CVE-2011-2107");
  script_bugtraq_id(48107);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-02-25 17:52:36 +0100 (Sat, 25 Feb 2017) $");
  script_tag(name:"creation_date", value:"2011-06-13 15:28:04 +0200 (Mon, 13 Jun 2011)");
  script_name("Adobe Products Unspecified Cross-Site Scripting Vulnerability June-2011 (Windows)");

  tag_summary =
"This host is installed with Adobe Flash Player, Adobe Reader or Acrobat and is
prone to cross-site scripting vulnerability.";

 tag_vuldetect =
"Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

  tag_insight =
"The flaw is caused by improper validation of certain unspecified input, which
allows remote attackers to inject arbitrary web script or HTML via unspecified
vectors.";

  tag_impact =
"Successful exploitation will allow attacker to execute arbitrary script code
in the browser of an unsuspecting user in the context of the affected site.

Impact Level: Application/System";

  tag_affected =
"Adobe Flash Player versions prior to 10.3.181.22 on Windows.
Adobe Reader and Acrobat X versions 10.0.3 and prior on Windows.";

  tag_solution =
"Upgrade to Adobe Flash Player version 10.3.181.22 or later.
For details refer, http://www.adobe.com/downloads/";



  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);

  script_tag(name:"qod_type", value:"registry");
  script_xref(name : "URL" , value : "http://www.adobe.com/support/security/bulletins/apsb11-13.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_flash_player_detect_win.nasl", "secpod_adobe_prdts_detect_win.nasl");
  script_require_keys("AdobeFlashPlayer/Win/Ver", "Adobe/Reader/Win/Ver", "Adobe/Acrobat/Win/Ver");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

## Variable Initialization
readerVer = "";
acrobatVer = "";
flashVer = "";

## Adobe Flash Player
flashVer = get_kb_item("AdobeFlashPlayer/Win/Ver");
if(flashVer)
{
  ## Check for Adobe Flash Player versions prior to 10.3.181.22
  if(version_is_less(version:flashVer, test_version:"10.3.181.22")){
    security_message(0);
  }
}


#CPE for adobe reader
CPE = "cpe:/a:adobe:acrobat_reader";

## Get Adobe Reader Version
if(readerVer = get_app_version(cpe:CPE, nvt:SCRIPT_OID))
{
  if(version_is_less_equal(version:readerVer, test_version:"10.0.3")){
    security_message(0);
  }
}

## Adobe Acrobat
acrobatVer = get_kb_item("Adobe/Acrobat/Win/Ver");
if(acrobatVer)
{
  if(version_is_less_equal(version:acrobatVer, test_version:"10.0.3")) {
    security_message(0);
  }
}
exit(0);
