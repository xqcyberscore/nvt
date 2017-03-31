###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_reader_u3d_mem_crptn_vuln_lin.nasl 5424 2017-02-25 16:52:36Z teissa $
#
# Adobe Reader 'U3D' Component Memory Corruption Vulnerability - Linux
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

CPE = "cpe:/a:adobe:acrobat_reader";
SCRIPT_OID = "1.3.6.1.4.1.25623.1.0.802544";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 5424 $");
  script_cve_id("CVE-2011-2462", "CVE-2011-4369");
  script_bugtraq_id(50922, 51092);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-02-25 17:52:36 +0100 (Sat, 25 Feb 2017) $");
  script_tag(name:"creation_date", value:"2011-12-09 12:52:04 +0530 (Fri, 09 Dec 2011)");
  script_name("Adobe Reader 'U3D' Component Memory Corruption Vulnerability - Linux");

  tag_summary =
"This host is installed with Adobe Reader and is prone to memory corruption
vulnerability.";

  tag_vuldetect =
"Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

  tag_insight =
"The flaw is due to an unspecified error while handling U3D data.";

  tag_impact =
"Successful exploitation will allow attackers to execute arbitrary code in the
context of the affected application or cause a denial of service.

Impact Level: Application";

  tag_affected =
"Adobe Reader versions 9.x through 9.4.6 on Linux";

  tag_solution =
"Upgrade to Adobe Reader version 9.4.7 or later,
For updates refer to http://www.adobe.com/";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/47133/");
  script_xref(name : "URL" , value : "http://www.adobe.com/support/security/advisories/apsa11-04.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_prdts_detect_lin.nasl");
  script_require_keys("Adobe/Reader/Linux/Version");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

## Get Reader Version
if(!readerVer = get_app_version(cpe:CPE, nvt:SCRIPT_OID)){
  exit(0);
}

if(readerVer =~ "^9")
{
  ## Check for Adobe Reader versions
  if(version_in_range(version:readerVer, test_version:"9.0", test_version2:"9.4.6"))
  {
    security_message(0);
    exit(0);
  }
}
