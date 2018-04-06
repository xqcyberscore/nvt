###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_flash_player_mult_vuln01_apr13_lin.nasl 9353 2018-04-06 07:14:20Z cfischer $
#
# Adobe Flash Player Multiple Vulnerabilities -01 April 13 (Linux)
#
# Authors:
# Arun Kallavi <karun@secpod.com>
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
  code or cause denial-of-service condition.
  Impact Level: System/Application";

tag_affected = "Adobe Flash Player 10.3.183.67 and earlier, and 11.x to 11.2.202.274
  on Linux";
tag_insight = "Multiple flaws due to,
  - Heap based overflow via unspecified vectors.
  - Integer overflow via unspecified vectors.
  - Use-after-free errors.";
tag_solution = "Upgrade to version 10.3.183.68 or 11.2.202.275,
  For updates refer to http://www.adobe.com/products/flash.html";
tag_summary = "This host is installed with Adobe Flash Player and is prone to
  multiple vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803375");
  script_version("$Revision: 9353 $");
  script_cve_id("CVE-2013-1375","CVE-2013-1371","CVE-2013-0650","CVE-2013-0646");
  script_bugtraq_id(58439,58438,58440,58436);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2013-04-18 13:31:05 +0530 (Thu, 18 Apr 2013)");
  script_name("Adobe Flash Player Multiple Vulnerabilities -01 April 13 (Linux)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/52590");
  script_xref(name : "URL" , value : "http://www.adobe.com/support/security/bulletins/apsb13-09.html");
  script_xref(name : "URL" , value : "https://www.cert.be/pro/advisories/adobe-flash-player-air-multiple-vulnerabilities-2");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_flash_player_detect_lin.nasl");
  script_mandatory_keys("AdobeFlashPlayer/Linux/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("version_func.inc");

## Variable Initialization
playerVer = "";

## Get Adobe Flash Player Version from KB
playerVer = get_kb_item("AdobeFlashPlayer/Linux/Ver");
if(!playerVer){
  exit(0);
}

## Check for Adobe Flash Player version prior to 10.3.183.68 or 11.2.202.275
if(version_is_less(version:playerVer, test_version:"10.3.183.68") ||
  version_in_range(version:playerVer, test_version:"11.0", test_version2:"11.2.202.274"))
{
  security_message(0);
  exit(0);
}
