###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_reader_mult_unspecified_vuln01_feb13_lin.nasl 6079 2017-05-08 09:03:33Z teissa $
#
# Adobe Reader Multiple Unspecified Vulnerabilities -01 Feb13 (Linux)
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
SCRIPT_OID = "1.3.6.1.4.1.25623.1.0.803417";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 6079 $");
  script_cve_id("CVE-2013-0640", "CVE-2013-0641");
  script_bugtraq_id(57931, 57947);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-05-08 11:03:33 +0200 (Mon, 08 May 2017) $");
  script_tag(name:"creation_date", value:"2013-02-19 19:06:59 +0530 (Tue, 19 Feb 2013)");
  script_name("Adobe Reader Multiple Unspecified Vulnerabilities -01 Feb13 (Linux)");

  tag_summary =
"This host is installed with Adobe Reader and is prone to multiple unspecified
vulnerabilities.";

  tag_vuldetect =
"Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

  tag_insight =
"The flaws are due to unspecified errors.";

  tag_impact =
"Successful exploitation will allow attacker to execute arbitrary code or cause
a denial of service via a crafted PDF document.

Impact Level: System/Application";

  tag_affected =
"Adobe Reader Version 9.x prior to 9.5.4 on Linux";

  tag_solution =
"Upgrade to Adobe Reader version 9.5.4 or later.
For updates refer to http://www.adobe.com";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/52196");
  script_xref(name : "URL" , value : "http://www.adobe.com/support/security/advisories/apsa13-02.html");
  script_xref(name : "URL" , value : "http://blogs.adobe.com/psirt/2013/02/adobe-reader-and-acrobat-vulnerability-report.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_prdts_detect_lin.nasl");
  script_mandatory_keys("Adobe/Reader/Linux/Version");
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

if(readerVer =~ "^9")
{
  # Check Adobe Reader version is 9.x <= 9.5.3
  if(version_in_range(version:readerVer, test_version:"9.0", test_version2: "9.5.3"))
  {
     security_message(0);
     exit(0);
  }
}
