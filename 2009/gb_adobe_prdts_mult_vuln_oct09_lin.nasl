###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_prdts_mult_vuln_oct09_lin.nasl 4865 2016-12-28 16:16:43Z teissa $
#
# Adobe Reader Multiple Vulnerabilities - Oct09 (Linux)
#
# Authors:
# Nikta MR <rnikita@secpod.com>
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

SCRIPT_OID = "1.3.6.1.4.1.25623.1.0.800958";
CPE = "cpe:/a:adobe:acrobat_reader";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 4865 $");
  script_cve_id("CVE-2009-2979", "CVE-2009-2980", "CVE-2009-2981", "CVE-2009-2982",
                "CVE-2009-2983", "CVE-2009-2984", "CVE-2009-2985", "CVE-2009-2986",
                "CVE-2009-2987", "CVE-2009-2988", "CVE-2009-2989", "CVE-2009-2990",
                "CVE-2009-2991", "CVE-2009-2992", "CVE-2009-2993", "CVE-2009-2994",
                "CVE-2009-2995", "CVE-2009-2996", "CVE-2009-2997", "CVE-2009-2998",
                "CVE-2009-3458", "CVE-2009-3459", "CVE-2009-3460", "CVE-2009-3462",
                "CVE-2009-3431");
  script_bugtraq_id(36686, 36687, 36688, 36691, 36667, 36690, 36680, 36682, 36693,
                    36665, 36669, 36689, 36694, 36681, 36671, 36678, 36677, 36600,
                    36638, 36696, 35148);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2016-12-28 17:16:43 +0100 (Wed, 28 Dec 2016) $");
  script_tag(name:"creation_date", value:"2009-10-22 15:34:45 +0200 (Thu, 22 Oct 2009)");
  script_name("Adobe Reader Multiple Vulnerabilities - Oct09 (Linux)");

  tag_summary =
"This host has Adobe Reader installed which is prone to multiple
vulnerabilities.";

  tag_vuldetect =
"Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

  tag_insight =
"For more information about the vulnerabilities refer the links mentioned in
references.";

  tag_impact =
"Successful exploitation allows remote attackers to execute arbitrary code,
write arbitrary files or folders to the filesystem, escalate local privileges,
or cause a denial of service on an affected system by tricking the user to
open a malicious PDF document.

Impact Level: System/Application";

  tag_affected =
"Adobe Reader version 7.x before 7.1.4, 8.x before 8.1.7 and 9.x before 9.2 on
Linux.";

  tag_solution =
"Upgrade to Adobe Reader versions 9.2, 8.1.7, or 7.1.4 or later.
For updates refer to http://www.adobe.com/downloads/";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/36983");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/53691");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/2851");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/2898");
  script_xref(name : "URL" , value : "http://securitytracker.com/alerts/2009/Oct/1023007.html");
  script_xref(name : "URL" , value : "http://www.adobe.com/support/security/bulletins/apsb09-15.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("General");
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

# Check for Adobe Reader version prior to 9.2 or 8.1.7 or 7.1.4
if(readerVer =~ "^(7|8|9)")
{
  if(version_in_range(version:readerVer, test_version:"7.0", test_version2:"7.1.3")||
     version_in_range(version:readerVer, test_version:"8.0", test_version2:"8.1.6")||
     version_in_range(version:readerVer, test_version:"9.0", test_version2:"9.1.3"))
  {
    security_message(0);
    exit(0);
  }
}
