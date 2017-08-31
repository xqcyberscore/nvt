###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_reader_dos_n_code_exec_vuln_macosx.nasl 6692 2017-07-12 09:57:43Z teissa $
#
# Adobe Reader Denial of Service & Code Execution Vulnerabilities (Mac OS X)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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

CPE = "cpe:/a:adobe:acrobat_reader";
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.804263";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 6692 $");
  script_cve_id("CVE-2010-3623", "CVE-2010-3631", "CVE-2010-3624");
  script_bugtraq_id(43731, 43733, 43736);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-07-12 11:57:43 +0200 (Wed, 12 Jul 2017) $");
  script_tag(name:"creation_date", value:"2014-04-16 11:35:51 +0530 (Wed, 16 Apr 2014)");
  script_name("Adobe Reader Denial of Service & Code Execution Vulnerabilities (Mac OS X)");

  tag_summary =
"This host is installed with Adobe Reader and is prone to denial of service and
code execution vulnerabilities.";

  tag_vuldetect =
"Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

  tag_insight =
"Flaws exist due to,
- An array-indexing error when parsing protocol handler parameters.
- An input validation error when parsing images.
- Improper sanitization of certain unspecified user-supplied input.";

  tag_impact =
"Successful exploitation will allow attackers to execute arbitrary code or
cause a denial of service.

Impact Level: System/Application";

  tag_affected =
"Adobe Reader version 8.x before 8.2.5 and 9.x before 9.4 on Mac OS X.";

  tag_solution =
"Upgrade to Adobe Reader 8.2.5 or 9.4 or later. For
updates refer to http://get.adobe.com/reader";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/41435");
  script_xref(name : "URL" , value : "http://www.adobe.com/support/security/bulletins/apsb10-21.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_macosx.nasl");
  script_mandatory_keys("Adobe/Reader/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

## Variable Initialization
readerVer = "";

## Get version
if(!readerVer = get_app_version(cpe:CPE, nvt:SCRIPT_OID)){
  exit(0);
}

if(readerVer && readerVer =~ "^(8|9)")
{
  ## Check Adobe Reader version
  if(version_in_range(version:readerVer, test_version:"8.0", test_version2:"8.2.4")||
     version_in_range(version:readerVer, test_version:"9.0", test_version2:"9.3.4"))
  {
    security_message(0);
    exit(0);
  }
}
