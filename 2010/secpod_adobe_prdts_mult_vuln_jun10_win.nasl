###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_adobe_prdts_mult_vuln_jun10_win.nasl 8210 2017-12-21 10:26:31Z cfischer $
#
# Adobe Flash Player/Air Multiple Vulnerabilities - June10 (Windows)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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

tag_impact = "Successful exploitation will allow attackers to obtain sensitive
  information or cause a denial of service.

  Impact Level: Application/System.";
tag_affected = "Adobe AIR version prior to 2.0.2.12610,

  Adobe Flash Player before 9.0.277.0 and 10.x before 10.1.53.64 on windows.";

tag_insight = "The flaws are due to input validation errors, memory corruptions,
  array indexing, use-after-free, integer and buffer overflows, and
  invalid pointers when processing malformed Flash content.";

tag_solution = "Update to Adobe  Air2.0.2.12610 or Adobe Flash Player 9.0.277.0 or 10.0.45.2,
  http://get.adobe.com/air
  http://www.adobe.com/support/flashplayer/downloads.html";

tag_summary = "This host is installed with Adobe Flash Player/Air and is prone to
  multiple vulnerabilities.";

if(description)
{
  script_id(902200);
  script_version("$Revision: 8210 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-21 11:26:31 +0100 (Thu, 21 Dec 2017) $");
  script_tag(name:"creation_date", value:"2010-06-22 13:34:32 +0200 (Tue, 22 Jun 2010)");
  script_cve_id("CVE-2008-4546", "CVE-2009-3793", "CVE-2010-1297", "CVE-2010-2160",
                "CVE-2010-2161", "CVE-2010-2162", "CVE-2010-2163", "CVE-2010-2164",
                "CVE-2010-2165", "CVE-2010-2166", "CVE-2010-2167", "CVE-2010-2169",
                "CVE-2010-2170", "CVE-2010-2171", "CVE-2010-2173", "CVE-2010-2174",
                "CVE-2010-2175", "CVE-2010-2176", "CVE-2010-2177", "CVE-2010-2178",
                "CVE-2010-2179", "CVE-2010-2180", "CVE-2010-2181", "CVE-2010-2182",
                "CVE-2010-2183", "CVE-2010-2184", "CVE-2010-2185", "CVE-2010-2186",
                "CVE-2010-2187", "CVE-2010-2188", "CVE-2010-2189");
  script_bugtraq_id(40759);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Adobe Flash Player/Air Multiple Vulnerabilities - June10 (Windows)");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/1421");
  script_xref(name : "URL" , value : "http://securitytracker.com/alerts/2010/Jun/1024086.html");
  script_xref(name : "URL" , value : "http://www.adobe.com/support/security/bulletins/apsb10-14.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPOd");
  script_family("General");
  script_dependencies("gb_adobe_flash_player_detect_win.nasl");
  script_mandatory_keys("Adobe/Air_or_Flash_or_Reader_or_Acrobat/Win/Installed");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

CPE = "cpe:/a:adobe:flash_player";
if(playerVer = get_app_version(cpe:CPE, nofork:TRUE))
{
  # Grep for version 10.x < 10.0.45.2, less than 9.0.277.0
  if(version_is_less(version:playerVer, test_version:"9.0.277.0") ||
     version_in_range(version:playerVer, test_version:"10.0", test_version2:"10.0.45.1"))
  {
    security_message(0);
    exit(0);
  }
}

CPE = "cpe:/a:adobe:adobe_air";
if(airVer = get_app_version(cpe:CPE))
{
  # Grep for version < 2.0.2.12610
  if(version_is_less(version:airVer, test_version:"2.0.2.12610")){
    security_message(0);
  }
}
