###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_prdts_mult_dos_vuln_aug09_win.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Adobe Flash Player/Air Multiple DoS Vulnerabilities - Aug09 (Windows)
#
# Authors:
# Sharath S <sharaths@secpod.com>
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
tag_affected = "Adobe AIR version prior to 1.5.2

  Adobe Flash Player 9 version prior to 9.0.246.0

  Adobe Flash Player 10 version prior to 10.0.32.18 on Windows";

tag_insight = "Multiple vulnerabilities which can be to exploited to cause memory
  corruption, null pointer, privilege escalation, heap-based buffer overflow,
  local sandbox bypass, and input validation errors when processing specially
  crafted web pages.";

tag_solution = "Update to Adobe Air 1.5.2 or Adobe Flash Player 9.0.246.0 or 10.0.32.18
  http://get.adobe.com/air
  http://www.adobe.com/support/flashplayer/downloads.html";

tag_summary = "This host is installed with Adobe Flash Player/Air and is prone to
  multiple Denial of Service vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800853");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-08-06 06:50:55 +0200 (Thu, 06 Aug 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-1863", "CVE-2009-1864", "CVE-2009-1865", "CVE-2009-1866",
                "CVE-2009-1867", "CVE-2009-1868", "CVE-2009-1869", "CVE-2009-1870");
  script_bugtraq_id(35900, 35904, 35906, 35901, 35905, 35902, 35907, 35908);
  script_name("Adobe Flash Player/Air Multiple DoS Vulnerabilities - Aug09 (Windows)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/35948/");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/2086");
  script_xref(name : "URL" , value : "http://www.adobe.com/support/security/bulletins/apsb09-10.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
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
  # Grep for version < 9.0.246.0 or 10.x < 10.0.32.18
  if(version_is_less(version:playerVer, test_version:"9.0.246.0") ||
     version_in_range(version:playerVer, test_version:"10.0",
                                        test_version2:"10.0.32.17"))
  {
    security_message(0);
    exit(0);
  }
}

CPE = "cpe:/a:adobe:adobe_air";
if(airVer = get_app_version(cpe:CPE))
{
  # Grep for version < 1.5.2
  if(version_is_less(version:airVer, test_version:"1.5.2")){
    security_message(0);
  }
}
