###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_flash_player_mult_vuln_macosx_mar12.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# Adobe Flash Player Multiple Vulnerabilities (Mac OS X) - Mar12
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
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

tag_impact = "Successful exploitation will allow remote attackers to gain sensitive
  information or execute arbitrary code in the context of the affected
  application or cause a denial of service condition.
  Impact Level: System/Application";
tag_affected = "Adobe Flash Player version before 10.3.183.16 on Mac OS X
  Adobe Flash Player version 11.x before 11.1.102.63 on Mac OS X";
tag_insight = "The flaws are due to an integer errors and unspecified error in Matrix3D
  component.";
tag_solution = "Upgrade to Adobe Flash Player version 10.3.183.16 or 11.1.102.63 or later,
  For updates refer to http://www.adobe.com/downloads/";
tag_summary = "This host is installed with Adobe Flash Player and is prone to
  multiple vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802812");
  script_version("$Revision: 9352 $");
  script_cve_id("CVE-2012-0769", "CVE-2012-0768");
  script_bugtraq_id(52299, 52297);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-03-12 18:30:17 +0530 (Mon, 12 Mar 2012)");
  script_name("Adobe Flash Player Multiple Vulnerabilities (Mac OS X) - Mar12");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/48281/");
  script_xref(name : "URL" , value : "http://www.adobe.com/support/security/bulletins/apsb12-05.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
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

# Variable Initialization
flashVer = NULL;

#Get Adobe Flash Player Version
flashVer = get_kb_item("Adobe/Flash/Player/MacOSX/Version");
if(isnull(flashVer)){
  exit(0);
}

## Check for Adobe Flash Player versions before 10.3.183.16 and 11.1.102.63
if(version_is_less(version:flashVer, test_version:"10.3.183.16")||
   version_in_range(version:flashVer, test_version:"11.0", test_version2:"11.1.102.62")){
  security_message(0);
}
