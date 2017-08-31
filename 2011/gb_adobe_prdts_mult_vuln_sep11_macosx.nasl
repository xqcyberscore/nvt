###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_prdts_mult_vuln_sep11_macosx.nasl 6477 2017-06-29 07:53:14Z cfischer $
#
# Adobe Reader and Acrobat Multiple Vulnerabilities September-2011 (Mac OS X)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (C) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.802168";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 6477 $");
  script_cve_id("CVE-2011-2431", "CVE-2011-2432", "CVE-2011-2433", "CVE-2011-2434",
                "CVE-2011-2435", "CVE-2011-2436", "CVE-2011-2437", "CVE-2011-2438",
                "CVE-2011-2439", "CVE-2011-2440", "CVE-2011-2441", "CVE-2011-2442");
  script_bugtraq_id(49582, 49572, 49576, 49577, 49578, 49579, 49580, 49583,
                    49581, 49584, 49575, 49585);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-06-29 09:53:14 +0200 (Thu, 29 Jun 2017) $");
  script_tag(name:"creation_date", value:"2011-10-28 16:17:13 +0200 (Fri, 28 Oct 2011)");
  script_name("Adobe Reader and Acrobat Multiple Vulnerabilities September-2011 (Mac OS X)");

  tag_summary =
"This host is installed with Adobe Reader/Acrobat and is prone to multiple
vulnerabilities.";

  tag_vuldetect =
"Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

  tag_insight =
"Multiple flaws are due to memory corruptions, and buffer overflow errors.";

  tag_impact =
"Successful exploitation will let attackers to execute arbitrary code via
unspecified vectors.

Impact Level: System/Application";

  tag_affected =
"Adobe Reader version 8.x through 8.3.0, 9.x through 9.4.5 and 10.x through 10.1
Adobe Acrobat version 8.x through 8.3.0, 9.x through 9.4.5 and 10.x through 10.1";

  tag_solution =
"Upgrade to Adobe Acrobat and Reader version 10.1.1, 9.4.6 or 8.3.1 or later.
For updates refer to http://www.adobe.com";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://www.adobe.com/support/security/bulletins/apsb11-24.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_macosx.nasl");
  script_mandatory_keys("Adobe/Air_or_Flash_or_Reader/MacOSX/Installed");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

## Variable Initialization
readerVer = "";
acrobatVer = "";

#CPE for adobe reader
CPE = "cpe:/a:adobe:acrobat_reader";

## Get Reader Version
if(readerVer = get_app_version(cpe:CPE, nvt:SCRIPT_OID))
{
  if(readerVer =~ "^(8|9|10)")
  {
    ## Check for Adobe Reader versions
    if(version_in_range(version:readerVer, test_version:"10.0", test_version2:"10.1") ||
       version_in_range(version:readerVer, test_version:"9.0", test_version2:"9.4.5") ||
       version_in_range(version:readerVer, test_version:"8.0", test_version2:"8.3.0")){
      security_message(0);
    }
  }
}

acrobatVer = get_kb_item("Adobe/Acrobat/MacOSX/Version");
if(acrobatVer)
{
  ## Check for Adobe Acrobat versions
  if(version_in_range(version:acrobatVer, test_version:"10.0", test_version2:"10.1") ||
     version_in_range(version:acrobatVer, test_version:"9.0", test_version2:"9.4.5") ||
     version_in_range(version:acrobatVer, test_version:"8.0", test_version2:"8.3.0")){
    security_message(0);
    exit(0);
  }
}
