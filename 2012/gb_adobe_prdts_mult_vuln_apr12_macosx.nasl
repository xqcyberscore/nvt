###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_prdts_mult_vuln_apr12_macosx.nasl 6022 2017-04-25 12:51:04Z teissa $
#
# Adobe Reader Multiple Vulnerabilities April-2012 (Mac OS X)
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
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.802749";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 6022 $");
  script_cve_id("CVE-2012-0777", "CVE-2012-0776", "CVE-2012-0774", "CVE-2012-0775");
  script_bugtraq_id(52950, 52952, 52951, 52949);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-04-25 14:51:04 +0200 (Tue, 25 Apr 2017) $");
  script_tag(name:"creation_date", value:"2012-04-17 13:03:11 +0530 (Tue, 17 Apr 2012)");
  script_name("Adobe Reader Multiple Vulnerabilities April-2012 (Mac OS X)");

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
"Successful exploitation will let attackers to bypass certain security
restrictions, execute arbitrary code via unspecified vectors or cause a denial
of service.

Impact Level: System/Application";

  tag_affected =
"Adobe Reader version 9.x to 9.5 and prior and 10.x to 10.1.2 on Mac OS X";

  tag_solution =
"Upgrade to Adobe Reader version 9.5.1 or 10.1.3 on later,
  For updates refer to http://www.adobe.com";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/48733");
  script_xref(name : "URL" , value : "http://www.securitytracker.com/id/1026908");
  script_xref(name : "URL" , value : "http://www.adobe.com/support/security/bulletins/apsb12-08.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_macosx.nasl");
  script_mandatory_keys("Adobe/Reader/MacOSX/Version");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

## Variable Initialization
readerVer = "";

## Function to check the versions of abode reader
function version_check(ver)
{
  if(version_in_range(version:ver, test_version:"9.0", test_version2:"9.5") ||
     version_in_range(version:ver, test_version:"10.0", test_version2:"10.1.2"))
  {
    security_message(0);
    exit(0);
  }
}

## Get Reader Version
if(!readerVer = get_app_version(cpe:CPE, nvt:SCRIPT_OID)){
  exit(0);
}

if(readerVer =~ "^(9|10)"){
  version_check(ver:readerVer);
}
