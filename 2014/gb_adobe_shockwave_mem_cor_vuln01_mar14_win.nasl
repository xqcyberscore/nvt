###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_shockwave_mem_cor_vuln01_mar14_win.nasl 2014-03-21 14:04:57Z Mar$
#
# Adobe Shockwave Player Memory Corruption Vulnerability Mar14 (Windows)
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:adobe:shockwave_player";
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.804517";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 6724 $");
  script_cve_id("CVE-2014-0505");
  script_bugtraq_id(66182);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-07-14 11:57:17 +0200 (Fri, 14 Jul 2017) $");
  script_tag(name:"creation_date", value:"2014-03-21 14:04:57 +0530 (Fri, 21 Mar 2014)");
  script_name("Adobe Shockwave Player Memory Corruption Vulnerability Mar14 (Windows)");

  tag_summary =
"This host is installed with Adobe Shockwave Player and is prone to memory
corruption vulnerability.";

  tag_vuldetect =
"Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

  tag_insight =
"Flaw is due to an unspecified error.";

  tag_impact =
"Successful exploitation will allow attackers to execute arbitrary code, cause
memory corruption and compromise a user's system.

Impact Level: System/Application";

  tag_affected =
"Adobe Shockwave Player version before 12.1.0.150 on Windows.";

  tag_solution =
"Upgrade to version 12.1.0.150 or later,
For updates refer to http://get.adobe.com/shockwave";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/57277");
  script_xref(name : "URL" , value : "https://www.hkcert.org/my_url/en/alert/14031701");
  script_xref(name : "URL" , value : "http://helpx.adobe.com/security/products/shockwave/apsb14-10.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_adobe_shockwave_player_detect.nasl");
  script_mandatory_keys("Adobe/ShockwavePlayer/Ver");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

## Variable Initialization
playerVer = "";

## Get version
if(!playerVer = get_app_version(cpe:CPE, nvt:SCRIPT_OID)){
  exit(0);
}

## Grep for vulnerable version
if(version_is_less(version:playerVer, test_version:"12.1.0.150"))
{
  security_message(0);
  exit(0);
}
