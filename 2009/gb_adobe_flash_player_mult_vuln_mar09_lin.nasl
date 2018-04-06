###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_flash_player_mult_vuln_mar09_lin.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Adobe Flash Player Multiple Vulnerabilities - Mar09 (Linux)
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

tag_solution = "Upgrade to version Adobe Flash Player 9.0.159.0 or 10.0.22.87
  http://get.adobe.com/flashplayer

  Update to version 1.5.1 for Adobe AIR
  http://get.adobe.com/air";

tag_impact = "Successful exploitation will allow remote attackers to cause remote code
  execution, compromise system privileges or may cause exposure of sensitive
  information.
  Impact Level: System/Application";
tag_affected = "Adobe AIR version prior to 1.5.1
  Adobe Flash Player 9 version prior to 9.0.159.0
  Adobe Flash Player 10 version prior to 10.0.22.87";
tag_insight = "- Error while processing multiple references to an unspecified object which
    can be exploited by tricking the user to access a malicious crafted
    SWF file.
  - Input validation error in the processing of SWF file.
  - Error while displaying the mouse pointer on Windows which may cause
    'Clickjacking' attacks.
  - Error in the Linux Flash Player binaries which can cause disclosure of
    sensitive information.";
tag_summary = "This host is installed with Adobe Products and is prone to
  multiple vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800360");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-03-10 11:59:23 +0100 (Tue, 10 Mar 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-0114", "CVE-2009-0519", "CVE-2009-0520",
                "CVE-2009-0521", "CVE-2009-0522");
  script_bugtraq_id(33890);
  script_name("Adobe Flash Player Multiple Vulnerabilities - Mar09 (Linux)");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/34012");
  script_xref(name : "URL" , value : "http://www.adobe.com/support/security/bulletins/apsb09-01.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_adobe_flash_player_detect_lin.nasl");
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

# Check for Adobe Flash Player version < 9.0.159.0/10.0.22.87
playerVer = get_kb_item("AdobeFlashPlayer/Linux/Ver");
if(playerVer != NULL)
{
  if(version_is_less(version:playerVer, test_version:"9.0.159.0") ||
     version_in_range(version:playerVer, test_version:"10.0",
                                         test_version2:"10.0.22.86"))
  {
    security_message(0);
    exit(0);
  }
}

# Check for Adobe Air version < 1.5.1
airVer = get_kb_item("Adobe/Air/Linux/Ver");
if(airVer =~ "^[0-9]")
{
  if(version_is_less(version:airVer, test_version:"1.5.1")){
    security_message(0);
  }
}
