###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_prdts_mult_bof_vuln_jun09_lin.nasl 4865 2016-12-28 16:16:43Z teissa $
#
# Adobe Reader Multiple BOF Vulnerabilities - Jun09 (Linux)
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (C) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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

SCRIPT_OID = "1.3.6.1.4.1.25623.1.0.800586";
CPE = "cpe:/a:adobe:acrobat_reader";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 4865 $");
  script_cve_id("CVE-2009-0198", "CVE-2009-0509", "CVE-2009-0510", "CVE-2009-0511",
                "CVE-2009-0512", "CVE-2009-1855", "CVE-2009-1856", "CVE-2009-1857",
                "CVE-2009-0889", "CVE-2009-0888", "CVE-2009-1858", "CVE-2009-1859",
                "CVE-2009-1861", "CVE-2009-2028");
  script_bugtraq_id(35274, 35282, 35289, 35291, 35293, 35294, 35295,35296, 35298,
                    35299,35301, 35302, 35303);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2016-12-28 17:16:43 +0100 (Wed, 28 Dec 2016) $");
  script_tag(name:"creation_date", value:"2009-06-16 15:11:01 +0200 (Tue, 16 Jun 2009)");
  script_name("Adobe Reader Multiple BOF Vulnerabilities - Jun09 (Linux)");

  tag_summary =
"This host has Adobe Reader installed, which is prone to multiple buffer
overflow vulnerabilities.";

  tag_vuldetect =
"Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

  tag_insight =
"Multiple flaws are reported in Adobe Reader. For more information refer,
http://www.adobe.com/support/security/bulletins/apsb09-07.html";

  tag_impact =
"Successful exploitation allows remote attackers to execute arbitrary code to
cause a stack based overflow via a specially crafted PDF, and could also take
complete control of the affected system and cause the application to crash.

Impact Level: System";

  tag_affected =
"Adobe Reader 7 before 7.1.3, 8 before 8.1.6, and 9 before 9.1.2";

  tag_solution =
"Upgrade to Adobe Reader version 9.1.2, 8.1.6 and 7.1.3
http://www.adobe.com/support/security/bulletins/apsb09-07.html";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://www.adobe.com/support/security/bulletins/apsb09-07.html");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/1547");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/34580");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Buffer overflow");
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

if(readerVer =~ "^(7|8|9)")
{
  if(version_in_range(version:readerVer, test_version:"7.0", test_version2:"7.1.2")||
     version_in_range(version:readerVer, test_version:"8.0", test_version2:"8.1.5")||
     version_in_range(version:readerVer, test_version:"9.0", test_version2:"9.1.1"))
  {
    security_message(0);
    exit(0);
  }
}
