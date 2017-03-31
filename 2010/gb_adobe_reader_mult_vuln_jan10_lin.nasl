###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_reader_mult_vuln_jan10_lin.nasl 5263 2017-02-10 13:45:51Z teissa $
#
# Adobe Reader Multiple Vulnerabilities -jan10 (Linux)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.800428";
CPE = "cpe:/a:adobe:acrobat_reader";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 5263 $");
  script_cve_id("CVE-2009-3953", "CVE-2009-3954", "CVE-2009-3955", "CVE-2009-3956",
                "CVE-2009-3957", "CVE-2009-3958", "CVE-2009-3959", "CVE-2009-4324");
  script_bugtraq_id(37758, 37761, 37757, 37763, 37760, 37759, 37756);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-02-10 14:45:51 +0100 (Fri, 10 Feb 2017) $");
  script_tag(name:"creation_date", value:"2010-01-16 12:13:24 +0100 (Sat, 16 Jan 2010)");
  script_name("Adobe Reader Multiple Vulnerabilities -jan10 (Linux)");

  tag_summary =
"This host is installed with Adobe Reader and is prone to multiple
vulnerabilities.";

  tag_vuldetect =
"Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

  tag_insight =
"For more information refer,
http://www.adobe.com/support/security/bulletins/apsb10-02.html";

  tag_impact =
"Successful exploitation will let the attacker cause memory corruption or
denial of service.

Impact Level: System/Application";

  tag_affected =
"Adobe Reader and Acrobat 9.x before 9.3 on Linux.";

  tag_solution =
"Apply the patch or upgrade Adobe Reader 9.3
http://www.adobe.com/downloads/
http://www.adobe.com/support/security/bulletins/apsb10-02.html

*****
NOTE: Please ignore this warning if the patch is already applied.
*****";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://www.adobe.com/support/security/bulletins/apsb10-02.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
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
  # Grep for Adobe Reader version prior to 9.x
  if(version_in_range(version:readerVer, test_version:"9.0", test_version2:"9.2"))
  {
    security_message(0);
    exit(0);
  }
}
