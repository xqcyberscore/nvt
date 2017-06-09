###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms13-078.nasl 6079 2017-05-08 09:03:33Z teissa $
#
# Microsoft FrontPage Information Disclosure Vulnerability (2825621)
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (c) 2013 SecPod, http://www.secpod.com
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.903321";
CPE = "cpe:/a:microsoft:frontpage";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 6079 $");
  script_cve_id("CVE-2013-3137");
  script_bugtraq_id(62185);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-05-08 11:03:33 +0200 (Mon, 08 May 2017) $");
  script_tag(name:"creation_date", value:"2013-09-11 11:12:46 +0530 (Wed, 11 Sep 2013)");
  script_name("Microsoft FrontPage Information Disclosure Vulnerability (2825621)");

  tag_summary =
"This host is missing an important security update according to Microsoft
Bulletin MS13-078.";

  tag_vuldetect =
"Get the vulnerable file version and check appropriate patch is applied
or not.";

  tag_insight =
"Flaw is due to an an unspecified information disclosure vulnerability.";

  tag_impact =
"Successful exploitation will allow attackers to disclose the contents
of a file on a target system.

Impact Level: Application";

  tag_affected =
"Microsoft FrontPage 2003 Service Pack 3";

  tag_solution =
"Run Windows Update and update the listed hotfixes or download and
update mentioned hotfixes in the advisory from the below link,
http://technet.microsoft.com/en-us/security/bulletin/ms13-078";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2825621");
  script_xref(name : "URL" , value : "http://technet.microsoft.com/en-us/security/bulletin/MS13-078");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_frontpage_detect.nasl");
  script_mandatory_keys("Microsoft/FrontPage/Ver");
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");
include("host_details.inc");
include("secpod_smb_func.inc");

## Variable Initialization
appPath = "";
pageVer = "";

## Get version from KB
appPath = get_app_location(cpe:CPE, nvt:SCRIPT_OID);

## Confirm the location
if(appPath && "Unable to find the install" >!< appPath)
{
  ## Get Version from Frontpg.exe
  pageVer = fetch_file_version(sysPath: appPath, file_name:"Frontpg.exe");
  if(!pageVer){
    exit(0);
  }

  ## Check for version
  if(version_in_range(version:pageVer, test_version:"11.0", test_version2:"11.0.8338"))
  {
    security_message(0);
    exit(0);
  }
}
