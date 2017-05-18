###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_reader_mult_vuln_apr12_lin.nasl 5988 2017-04-20 09:02:29Z teissa $
#
# Adobe Reader Multiple Vulnerabilities April-2012 (Linux)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (C) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:adobe:acrobat_reader";
SCRIPT_OID = "1.3.6.1.4.1.25623.1.0.802747";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 5988 $");
  script_cve_id("CVE-2012-0777", "CVE-2012-0776", "CVE-2012-0774", "CVE-2012-0775");
  script_bugtraq_id(52950, 52952, 52951, 52949);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-04-20 11:02:29 +0200 (Thu, 20 Apr 2017) $");
  script_tag(name:"creation_date", value:"2012-04-16 19:08:36 +0530 (Mon, 16 Apr 2012)");
  script_name("Adobe Reader Multiple Vulnerabilities April-2012 (Linux)");

  tag_summary =
"This host is installed with Adobe Reader and is prone to multiple
vulnerabilities.";

  tag_vuldetect =
"Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

  tag_insight =
"The flaws are due to
- An unspecified error when handling JavaScript/JavaScript API can be exploited
to corrupt memory.
- An integer overflow error when handling True Type Font (TTF) can be exploited
to corrupt memory.
- The application loads executables (msiexec.exe) in an insecure manner.";

  tag_impact =
"Successful exploitation will let attackers to bypass certain security restrictions,
execute arbitrary code via unspecified vectors or cause a denial of service.

Impact Level: System/Application";

  tag_affected =
"Adobe Reader version 9.x to 9.4.6 on Linux";

  tag_solution =
"Upgrade to Adobe Reader version 9.5.1 or later,
For updates refer to http://www.adobe.com/";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/48733/");
  script_xref(name : "URL" , value : "http://www.securitytracker.com/id/1026908");
  script_xref(name : "URL" , value : "http://www.adobe.com/support/security/bulletins/apsb12-08.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_prdts_detect_lin.nasl");
  script_mandatory_keys("Adobe/Reader/Linux/Version");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

## Variable Initialization
readerVer = "";

## Get Reader Version
if(!readerVer = get_app_version(cpe:CPE, nvt:SCRIPT_OID)){
  exit(0);
}

if(readerVer =~ "^9")
{
  ## Check for Adobe Reader versions
  if(version_in_range(version:readerVer, test_version:"9.0", test_version2:"9.4.6")){
    security_message(0);
  }
}
