###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_adobe_prdts_bof_vuln_lin.nasl 5055 2017-01-20 14:08:39Z teissa $
#
# Buffer Overflow Vulnerability in Adobe Reader (Linux)
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (C) 2009 SecPod, http://www.secpod.com
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

SCRIPT_OID = "1.3.6.1.4.1.25623.1.0.900321";
CPE = "cpe:/a:adobe:acrobat_reader";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 5055 $");
  script_cve_id("CVE-2009-0658", "CVE-2009-0927");
  script_bugtraq_id(33751, 34169, 34229);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-01-20 15:08:39 +0100 (Fri, 20 Jan 2017) $");
  script_tag(name:"creation_date", value:"2009-03-03 06:56:37 +0100 (Tue, 03 Mar 2009)");
  script_name("Buffer Overflow Vulnerability in Adobe Reader (Linux)");

  tag_summary =
"This host has Adobe Reader installed, and is prone to buffer overflow
vulnerability.";

  tag_vuldetect =
"Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

  tag_insight =
"This issue is due to error in array indexing while processing JBIG2 streams
and unspecified vulnerability related to a JavaScript method.";

  tag_impact =
"This can be exploited to corrupt arbitrary memory via a specially crafted PDF
file, related to a non-JavaScript function call and to execute arbitrary code
in context of the affected application.

Impact Level: System/Application";

  tag_affected =
"Adobe Reader version 9.x < 9.1, 8.x < 8.1.4, 7.x < 7.1.1 on Linux";

  tag_solution =
"Upgrade to Adobe Reader version 9.1 or 8.1.4 or later.
http://www.adobe.com/support/downloads/product.jsp?product=10&platform=Unix";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/33901");
  script_xref(name : "URL" , value : "http://www.adobe.com/support/security/bulletins/apsb09-03.html");
  script_xref(name : "URL" , value : "http://www.adobe.com/support/security/bulletins/apsb09-04.html");
  script_xref(name : "URL" , value : "http://www.adobe.com/support/security/advisories/apsa09-01.html");
  script_xref(name : "URL" , value : "http://downloads.securityfocus.com/vulnerabilities/exploits/33751-PoC.pl");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Buffer overflow");
  script_dependencies("gb_adobe_prdts_detect_lin.nasl");
  script_require_keys("Adobe/Reader/Linux/Version");
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

# Check for Adobe Reader version prior to 9.1.0 or 8.1.4 or 7.1.1
if(readerVer =~ "^(7|8|9)")
{
  if(version_in_range(version:readerVer, test_version:"7.0", test_version2:"7.1.0")||
     version_in_range(version:readerVer, test_version:"8.0", test_version2:"8.1.3")||
     readerVer =~ "9.0")
  {
    security_message(0);
    exit(0);
  }
}
