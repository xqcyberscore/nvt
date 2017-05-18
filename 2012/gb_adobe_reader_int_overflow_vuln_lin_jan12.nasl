###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_reader_int_overflow_vuln_lin_jan12.nasl 5940 2017-04-12 09:02:05Z teissa $
#
# Adobe Reader Integer Overflow Vulnerability - Jan 12 (Linux)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
SCRIPT_OID = "1.3.6.1.4.1.25623.1.0.802421";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 5940 $");
  script_cve_id("CVE-2011-4374");
  script_bugtraq_id(51557);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-04-12 11:02:05 +0200 (Wed, 12 Apr 2017) $");
  script_tag(name:"creation_date", value:"2012-01-23 15:55:01 +0530 (Mon, 23 Jan 2012)");
  script_name("Adobe Reader Integer Overflow Vulnerability - Jan 12 (Linux)");

  tag_summary =
"This host is installed with Adobe Reader and is prone to integer overflow
vulnerability.";

  tag_vuldetect =
"Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

  tag_insight =
"The flaw is due to an integer overflow error, which allow the attackers to
execute arbitrary code via unspecified vectors.";

  tag_impact =
"Successful exploitation will allow the attackers to execute arbitrary code
via unspecified vectors.

Impact Level: Application";

  tag_affected =
"Adobe Reader version 9.x before 9.4.6 on Linux.";

  tag_solution =
"Upgrade Adobe Reader to 9.4.6 or later,
For updates refer to http://www.adobe.com/";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);

  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name : "URL" , value : "http://www.adobe.com/support/security/bulletins/apsb11-24.html");
  script_xref(name : "URL" , value : "http://people.canonical.com/~ubuntu-security/cve/2011/CVE-2011-4374.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Buffer overflow");
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
  ## Check for Adobe Reader versions 9.x and 9.4.5
  if(version_in_range(version:readerVer, test_version:"9.0", test_version2:"9.4.5")){
    security_message(0);
  }
}
