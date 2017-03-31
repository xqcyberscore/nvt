###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_flash_professional_jpg_obj_bof_vuln_macosx.nasl 3563 2016-06-20 14:55:04Z benallard $
#
# Adobe Flash Professional JPG Object Processing BOF Vulnerability (Mac OS X)
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

tag_impact = "Successful exploitation will allow attackers to execute arbitrary code.
  Impact Level: Application/System";
tag_affected = "Adobe Flash Professional version CS5.5.1(11.5.1.349) and prior on Mac OS X";
tag_insight = "The flaw is due to an error in 'Flash.exe' when allocating memory to
  process a JPG object using its image dimensions.";
tag_solution = "Upgrade to Adobe Flash Professional version CS6 or later,
  For updates refer to http://www.adobe.com/downloads/";
tag_summary = "This host is installed with Adobe Flash Professional and is prone
  to buffer overflow vulnerability.";

if(description)
{
  script_id(802785);
  script_version("$Revision: 3563 $");
  script_cve_id("CVE-2012-0778");
  script_bugtraq_id(53419);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2016-06-20 16:55:04 +0200 (Mon, 20 Jun 2016) $");
  script_tag(name:"creation_date", value:"2012-05-16 12:09:06 +0530 (Wed, 16 May 2012)");
  script_name("Adobe Flash Professional JPG Object Processing BOF Vulnerability (Mac OS X)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/47116/");
  script_xref(name : "URL" , value : "http://securitytracker.com/id/1027045");
  script_xref(name : "URL" , value : "http://www.adobe.com/support/security/bulletins/apsb12-12.html");

  script_summary("Check for the version of Adobe Flash Professional on Mac OS X");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_adobe_flash_professional_detect_macosx.nasl");
  script_require_keys("Adobe/Flash/Prof/MacOSX/Version");
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

## Variable Initiliazation
flashVer = "";

flashVer = get_kb_item("Adobe/Flash/Prof/MacOSX/Version");
if(!flashVer){
  exit(0);
}

## Check for Adobe Flash Professional versions <= CS5.5.1 (11.5.1.349)
if(version_is_less_equal(version:flashVer, test_version:"11.5.1.349")){
  security_message(0);
}
