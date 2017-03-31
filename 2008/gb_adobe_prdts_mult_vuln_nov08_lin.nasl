###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_prdts_mult_vuln_nov08_lin.nasl 4218 2016-10-05 14:20:48Z teissa $
#
# Adobe Reader/Acrobat Multiple Vulnerabilities - Nov08 (Linux)
#
# Authors:
# Chandan S <schandan@secpod.com>
#
# Copyright:
# Copyright (C) 2008 Greenbone Networks GmbH, http://www.greenbone.net
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

SCRIPT_OID = "1.3.6.1.4.1.25623.1.0.800051";
CPE = "cpe:/a:adobe:acrobat_reader";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 4218 $");
  script_cve_id("CVE-2008-2992", "CVE-2008-2549", "CVE-2008-4812",
                "CVE-2008-4813", "CVE-2008-4817", "CVE-2008-4816",
                "CVE-2008-4814", "CVE-2008-4815");
  script_bugtraq_id(30035, 32100);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2016-10-05 16:20:48 +0200 (Wed, 05 Oct 2016) $");
  script_tag(name:"creation_date", value:"2008-11-05 13:21:04 +0100 (Wed, 05 Nov 2008)");
  script_name("Adobe Reader/Acrobat Multiple Vulnerabilities - Nov08 (Linux)");

  tag_summary =
"This host has Adobe Reader/Acrobat installed, which is/are prone to multiple
vulnerabilities.";

  tag_vuldetect =
"Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

  tag_insight =
"The flaws are due to,
- a boundary error when parsing format strings containing a floating point
specifier in the util.printf() Javascript function.
- improper parsing of type 1 fonts.
- bounds checking not being performed after allocating an area of memory.";

  tag_impact =
"Successful exploitation allows remote attackers to execute arbitrary code to
cause a stack based overflow via a specially crafted PDF, and could also take
complete control of the affected system and cause the application to crash.

Impact Level: System";

  tag_affected =
"Adobe Reader/Acrobat versions 8.1.2 and prior - Linux(All)";

  tag_solution =
"Upgrade to 8.1.3 or higher versions,
http://www.adobe.com/products/";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://www.adobe.com/support/security/bulletins/apsb08-19.html");
  script_xref(name : "URL" , value : "http://www.coresecurity.com/content/adobe-reader-buffer-overflow");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_prdts_detect_lin.nasl");
  script_mandatory_keys("Adobe/Reader/Linux/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

## Variable Initialization
adobeVer = "";

## Get version
if(!adobeVer = get_app_version(cpe:CPE, nvt:SCRIPT_OID)){
  exit(0);
}

if(version_is_less_equal(version:adobeVer, test_version:"8.1.2"))
{
  security_message(0);
  exit(0);
}
