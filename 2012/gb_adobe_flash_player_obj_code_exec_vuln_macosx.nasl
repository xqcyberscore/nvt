###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_flash_player_obj_code_exec_vuln_macosx.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# Adobe Flash Player Object Confusion Remote Code Execution Vulnerability (Mac OS X)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_insight = "The flaw is due to an error related to object confusion.

  NOTE: Further information is not available.";

tag_impact = "Successful exploitation will let attackers to create crafted Flash content
  that, when loaded by the target user, will trigger an object confusion flaw
  and execute arbitrary code on the target system.
  Impact Level: System/Application";
tag_affected = "Adobe Flash Player version prior to 10.3.183.19 on Mac OS X
  Adobe Flash Player version 11.x prior to 11.2.202.235 on Mac OS X";
tag_solution = "Upgrade to Adobe Flash Player version 10.3.183.19 or 11.2.202.235 or later,
  For details refer, http://www.adobe.com/downloads/";
tag_summary = "This host is installed with Adobe Flash Player and is prone to
  object confusion remote code execution vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802773");
  script_version("$Revision: 9352 $");
  script_cve_id("CVE-2012-0779");
  script_bugtraq_id(53395);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-05-08 14:44:50 +0530 (Tue, 08 May 2012)");
  script_name("Adobe Flash Player Object Confusion Remote Code Execution Vulnerability (Mac OS X)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/49096/");
  script_xref(name : "URL" , value : "http://securitytracker.com/id/1027023");
  script_xref(name : "URL" , value : "http://www.adobe.com/support/security/bulletins/apsb12-09.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_macosx.nasl");
  script_require_keys("Adobe/Flash/Player/MacOSX/Version");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("version_func.inc");

## Variable Initialization
flashVer = "";

## Get the version
flashVer = get_kb_item("Adobe/Flash/Player/MacOSX/Version");
if(!flashVer){
  exit(0);
}

## Check for Adobe Flash Player versions prior to 10.3.183.19 and 11.2.202.235
if(version_is_less(version:flashVer, test_version:"10.3.183.19") ||
   version_in_range(version:flashVer, test_version:"11.0",  test_version2:"11.2.202.233")){
  security_message(0);
}
