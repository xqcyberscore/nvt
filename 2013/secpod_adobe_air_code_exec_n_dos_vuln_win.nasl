###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_adobe_air_code_exec_n_dos_vuln_win.nasl 2933 2016-03-24 08:20:46Z benallard $
#
# Adobe Air Code Execution and DoS Vulnerabilities (Windows)
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (c) 2013 SecPod, http://www.secpod.com
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

tag_impact = "
  Impact Level: System/Application";

if(description)
{
  script_id(903319);
  script_version("$Revision: 2933 $");
  script_cve_id("CVE-2012-0772", "CVE-2012-0773", "CVE-2012-0724", "CVE-2012-0725");
  script_bugtraq_id(52748, 52916, 52914);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2016-03-24 09:20:46 +0100 (Thu, 24 Mar 2016) $");
  script_tag(name:"creation_date", value:"2013-08-26 14:09:42 +0530 (Mon, 26 Aug 2013)");
  script_name("Adobe Air Code Execution and DoS Vulnerabilities (Windows)");

  tag_summary =
"This host is installed with Air and is prone to code execution and denial of
service vulnerabilities.";

  tag_vuldetect =
"Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

  tag_insight =
"The flaws are due to
- An error within an ActiveX Control when checking the URL security domain.
- An unspecified error within the NetStream class.";

  tag_impact =
"Successful exploitation will allow remote attackers to execute arbitrary
code or cause a denial of service (memory corruption) via unknown vectors.";

  tag_affected =
"Adobe AIR version prior to 3.2.0.2070 on Windows";

  tag_solution =
"Update to Adobe Air version 3.2.0.2070 or later,
For updates refer to http://get.adobe.com/air";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/48623");
  script_xref(name : "URL" , value : "http://www.securitytracker.com/id/1026859");
  script_xref(name : "URL" , value : "http://www.adobe.com/support/security/bulletins/apsb12-07.html");
  script_summary("Check for the version of Adobe Air on Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 SecPod");
  script_family("General");
  script_dependencies("gb_adobe_flash_player_detect_win.nasl");
  script_mandatory_keys("Adobe/Air/Win/Ver");
  exit(0);
}


include("version_func.inc");

## Variable Initialization
airVer = "";

## Check for Adobe Air
airVer = get_kb_item("Adobe/Air/Win/Ver");
if(airVer)
{
  ## Grep for version < 3.2.0.2070
  if(version_is_less(version:airVer, test_version:"3.2.0.2070"))
  {
    security_message(0);
    exit(0);
  }
}
