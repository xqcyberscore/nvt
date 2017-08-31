###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_digital_edition_dos_vuln_win.nasl 6769 2017-07-20 09:56:33Z teissa $
#
# Adobe Digital Edition Denial of Service Vulnerability (Windows)
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

CPE = "cpe:/a:adobe:digital_editions";
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.804301";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 6769 $");
  script_cve_id("CVE-2014-0494");
  script_bugtraq_id(65091);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-07-20 11:56:33 +0200 (Thu, 20 Jul 2017) $");
  script_tag(name:"creation_date", value:"2014-02-03 14:43:16 +0530 (Mon, 03 Feb 2014)");
  script_name("Adobe Digital Edition Denial of Service Vulnerability (Windows)");

  tag_summary =
"The host is installed with Adobe Digital Edition and is prone to
denial-of-service vulnerability.";

  tag_vuldetect =
"Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

  tag_insight =
"The flaw is due to an unspecified error and can be exploited to cause memory
corruption.";

  tag_impact =
"Successful exploitation will allow remote attackers to conduct denial of
service or execute an arbitrary code.

Impact Level: System/Application";

  tag_affected =
"Adobe Digital Edition version 2.0.1 on Windows.";

  tag_solution =
"Upgrade to Adobe Digital Edition 3.0 or later,
For updates refer to http://www.adobe.com/products/digital-editions/download.html";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/56578/");
  script_xref(name : "URL" , value : "http://helpx.adobe.com/security/products/Digital-Editions/apsb14-03.html");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_dependencies("gb_adobe_digital_edition_detect_win.nasl");
  script_mandatory_keys("AdobeDigitalEdition/Win/Ver");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

## Variable Initialization
ediVer = "";

## Get version
if(!ediVer = get_app_version(cpe:CPE, nvt:SCRIPT_OID)){
  exit(0);
}

## Grep for vulnerable version
if(version_is_equal(version:ediVer, test_version:"2.0.1"))
{
  security_message(0);
  exit(0);
}
