###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_reader_etd_file_dos_vuln_lin.nasl 6715 2017-07-13 09:57:40Z teissa $
#
# Adobe Reader '.ETD File' Denial of Service Vulnerability (Linux)
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
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.804386";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 6715 $");
  script_cve_id("CVE-2004-1153");
  script_bugtraq_id(11934);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-07-13 11:57:40 +0200 (Thu, 13 Jul 2017) $");
  script_tag(name:"creation_date", value:"2014-04-10 14:59:53 +0530 (Thu, 10 Apr 2014)");
  script_name("Adobe Reader '.ETD File' Denial of Service Vulnerability (Linux)");

  tag_summary =
"This host is installed with Adobe Reader and is prone to denial of service
vulnerability.";

  tag_vuldetect =
"Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

  tag_insight =
"Flaw is due to the format string error in '.etd' file.";

  tag_impact =
"Successful exploitation will allow attackers to execute arbitrary code on
the system and gain sensitive information.

Impact Level: System/Application";

  tag_affected =
"Adobe Reader version 6.0.0 through 6.0.2 on Linux.";

  tag_solution =
"Upgrade to Adobe Reader version 6.0.3 or later. For updates refer to
http://get.adobe.com/reader";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/18478");
  script_xref(name : "URL" , value : "http://archives.neohapsis.com/archives/bugtraq/2004-12/0147.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Denial of Service");
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

if(readerVer && readerVer =~ "6")
{
  ## Check Adobe Reader vulnerable versions
  if(version_in_range(version:readerVer, test_version:"6.0.0", test_version2:"6.0.2"))
  {
    security_message(0);
    exit(0);
  }
}
