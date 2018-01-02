###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_prdts_mult_vuln_dec09_win.nasl 8210 2017-12-21 10:26:31Z cfischer $
#
# Adobe Flash Player/Air Multiple Vulnerabilities - dec09 (Windows)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary code,
  gain elevated privileges, gain knowledge of certain information and conduct
  clickjacking attacks.

  Impact Level: System/Application";

tag_affected = "Adobe AIR version prior to 1.5.3

  Adobe Flash Player 10 version prior to 10.0.42.34 on Windows";

tag_insight = "The multiple Flaws are due to:

  - An error occurred while parsing JPEG dimensions contained within an SWF file
    can be exploited to cause a heap-based buffer overflow.

  - An unspecified error may allow injection of data and potentially lead to
    execution of arbitrary code.

  - An unspecified error possibly related to 'getProperty()' can be exploited
    to corrupt memory and may allow execution of arbitrary code.

  - An unspecified error can be exploited to corrupt memory and may allow
    execution of arbitrary code.

  - An integer overflow error when generating ActionScript exception handlers
    in 'Verifier::parseExceptionHandlers()' can be exploited to corrupt memory.

  - Various unspecified errors may potentially allow execution of arbitrary code.

  - An error may disclose information about local file names.";

tag_solution = "Update to Adobe Air 1.5.3 or Adobe Flash Player 10.0.42.34
  http://get.adobe.com/air
  http://www.adobe.com/support/flashplayer/downloads.html";

tag_summary = "This host is installed with Adobe Flash Player/Air and is prone to
  multiple vulnerabilities.";

if(description)
{
  script_id(801083);
  script_version("$Revision: 8210 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-21 11:26:31 +0100 (Thu, 21 Dec 2017) $");
  script_tag(name:"creation_date", value:"2009-12-17 08:14:37 +0100 (Thu, 17 Dec 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-3794", "CVE-2009-3796", "CVE-2009-3797", "CVE-2009-3798",
                "CVE-2009-3799", "CVE-2009-3800", "CVE-2009-3951");
  script_bugtraq_id(37266, 37270, 37273, 37275, 37267, 37269, 37272 );
  script_name("Adobe Flash Player/Air Multiple Vulnerabilities - dec09 (Windows)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/37584");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/3456");
  script_xref(name : "URL" , value : "http://www.adobe.com/support/security/bulletins/apsb09-19.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
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
  # Grep for version 10.x < 10.0.32.18
  if(version_in_range(version:playerVer, test_version:"10.0", test_version2:"10.0.42.33")) {
    security_message(0);
  }
}

CPE = "cpe:/a:adobe:adobe_air";
if(airVer = get_app_version(cpe:CPE))
{
  # Grep for version < 1.5.3
  if(version_is_less(version:airVer, test_version:"1.5.3")){
    security_message(0);
  }
}
