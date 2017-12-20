###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apple_itunes_memory_corruption_vuln_win.nasl 8169 2017-12-19 08:42:31Z cfischer $
#
# Apple iTunes ActiveX Control Memory Corruption Vulnerability (Windows)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

CPE = "cpe:/a:apple:itunes";
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.803765";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 8169 $");
  script_cve_id("CVE-2013-1035");
  script_bugtraq_id(62486);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-12-19 09:42:31 +0100 (Tue, 19 Dec 2017) $");
  script_tag(name:"creation_date", value:"2013-09-27 15:45:01 +0530 (Fri, 27 Sep 2013)");
  script_name("Apple iTunes ActiveX Control Memory Corruption Vulnerability (Windows)");

  tag_summary =
"This host is installed with Apple iTunes and is prone to memory corruption
vulnerability.";

  tag_vuldetect =
"Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

  tag_insight =
"The flaw is due to an error within an ActiveX Control.";

  tag_impact =
"Successful exploitation will allow attackers to execute arbitrary code and
or cause denial of service.

Impact Level: Application";

  tag_affected =
"Apple iTunes before 11.1 on windows";

  tag_solution =
"Upgrade to Apple iTunes version 11.1 or later,
For updates refer to http://www.apple.com/itunes";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://support.apple.com/kb/HT5936");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/54893");
  script_xref(name : "URL" , value : "http://seclists.org/bugtraq/2013/Sep/84");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_apple_itunes_detection_win_900123.nasl");
  script_mandatory_keys("iTunes/Win/Installed");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

## Variable Initialization
ituneVer = "";

## Get version
if(!ituneVer = get_app_version(cpe:CPE, nvt:SCRIPT_OID)){
  exit(0);
}

if(version_is_less(version:ituneVer, test_version:"11.1")){
  security_message(0);
}
