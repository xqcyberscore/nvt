###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nuance_pdf_reader_bof_vuln_apr14.nasl 6750 2017-07-18 09:56:47Z teissa $
#
# Nuance PDF Reader 'pdfcore8.dll' Buffer Overflow Vulnerability Apr14
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

CPE = "cpe:/a:nuance:pdf_reader";
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.804360";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 6750 $");
  script_cve_id("CVE-2013-0732");
  script_bugtraq_id(60315);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-07-18 11:56:47 +0200 (Tue, 18 Jul 2017) $");
  script_tag(name:"creation_date", value:"2014-04-04 13:11:15 +0530 (Fri, 04 Apr 2014)");
  script_name("Nuance PDF Reader 'pdfcore8.dll' Buffer Overflow Vulnerability Apr14");

  tag_summary =
"The host is installed with Nuance PDF Reader and is prone to buffer overflow
vulnerability.";

  tag_vuldetect =
"Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

  tag_insight =
"The flaw is due to an error in 'pdfcore8.dll' when processing naming table
entries within embedded TTF files.";

  tag_impact =
"Successful exploitation will allow remote attackers to conduct denial of
service or possibly execution of arbitrary code.

Impact Level: System/Application";

  tag_affected =
"Nuance PDF Reader version before 8.1";

  tag_solution =
"Upgrade to Nuance PDF Reader version 8.1 or later. For updates refer,
http://www.nuance.com/products/pdf-reader/index.htm";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);

  script_xref(name : "URL" , value : "http://secunia.com/advisories/51943");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/84695");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_family("Buffer overflow");
  script_dependencies("gb_nuance_pdf_reader_detect_win.nasl");
  script_mandatory_keys("Nuance/PDFReader/Win/Ver");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

## Variable Initialization
nuaVer = "";

## Get version
if(!nuaVer = get_app_version(cpe:CPE, nvt:SCRIPT_OID)){
  exit(0);
}

## Grep for vulnerable version,8.1==8.10.1302
if(version_is_less(version:nuaVer, test_version:"8.10.1302"))
{
  security_message(0);
  exit(0);
}
