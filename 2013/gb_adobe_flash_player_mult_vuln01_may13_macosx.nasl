###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_flash_player_mult_vuln01_may13_macosx.nasl 9353 2018-04-06 07:14:20Z cfischer $
#
# Adobe Flash Player Multiple Vulnerabilities -01 May 13 (Mac OS X)
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  code on the target system or cause a denial of service (memory corruption)
  via unspecified vectors.
  Impact Level: System/Application";

tag_affected = "Adobe Flash Player version before 10.3.183.76 and 11.x before 11.7.700.170
  on Mac OS X";
tag_insight = "Multiple memory corruption flaws due to improper sanitation of user
  supplied input via a file.";
tag_solution = "Update to Adobe Flash Player version 10.3.183.86 or 11.7.700.202 or later
  For updates refer to  http://get.adobe.com/flashplayer";
tag_summary = "This host is installed with Adobe Flash Player and is prone to
  multiple vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803495");
  script_version("$Revision: 9353 $");
  script_cve_id("CVE-2013-3335", "CVE-2013-3334", "CVE-2013-3333", "CVE-2013-3332",
                "CVE-2013-3331", "CVE-2013-3330", "CVE-2013-3329", "CVE-2013-3328",
                "CVE-2013-3327", "CVE-2013-3326", "CVE-2013-3325", "CVE-2013-3324",
                                                                   "CVE-2013-2728");
  script_bugtraq_id(59901, 59900, 59899, 59898, 59897, 59896, 59895,
                           59894, 59893, 59892, 59891, 59890, 59889);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2013-05-21 13:55:34 +0530 (Tue, 21 May 2013)");
  script_name("Adobe Flash Player Multiple Vulnerabilities -01 May 13 (Mac OS X)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/53419");
  script_xref(name : "URL" , value : "http://www.adobe.com/support/security/bulletins/apsb13-14.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_macosx.nasl");
  script_mandatory_keys("Adobe/Flash/Player/MacOSX/Version");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("version_func.inc");

## Variable Initialization
playerVer = "";

## Check for Adobe Flash Player
playerVer = get_kb_item("Adobe/Flash/Player/MacOSX/Version");
if(playerVer)
{
  ## Grep for vulnerable version
  if(version_is_less(version:playerVer, test_version:"10.3.183.75") ||
     version_in_range(version:playerVer, test_version:"11.0", test_version2:"11.7.700.169"))
  {
    security_message(0);
    exit(0);
  }
}
