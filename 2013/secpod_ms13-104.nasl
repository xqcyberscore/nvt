###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms13-104.nasl 9353 2018-04-06 07:14:20Z cfischer $
#
# Microsoft Office Information Disclosure Vulnerability (2909976)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2013 SecPod, http://www.secpod.com
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.903419");
  script_version("$Revision: 9353 $");
  script_cve_id("CVE-2013-5054");
  script_bugtraq_id(64092);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2013-12-11 11:06:48 +0530 (Wed, 11 Dec 2013)");
  script_name("Microsoft Office Information Disclosure Vulnerability (2909976)");

  tag_summary =
"This host is missing an important security update according to
Microsoft Bulletin MS13-104.";

  tag_vuldetect =
"Get the vulnerable file version and check appropriate patch is applied
or not.";

  tag_insight =
"The flaw is due to the application improperly handling response while
attempting to open a hosted file and can be exploited to disclose tokens
used to authenticate the user on a SharePoint or other Microsoft Office
server site.";

  tag_impact =
"Successful exploitation will allow remote attackers to disclose certain
sensitive information.

Impact Level: Application ";

  tag_affected =
"Microsoft Office 2013";

  tag_solution =
"Run Windows Update and update the listed hotfixes or download and update
mentioned hotfixes in the advisory from the below link,
https://technet.microsoft.com/en-us/security/bulletin/ms13-104";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/55997");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2850064");
  script_xref(name : "URL" , value : "http://www.securitytracker.com/id/1029464");
  script_xref(name : "URL" , value : "https://technet.microsoft.com/en-us/security/bulletin/ms13-104");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_mandatory_keys("MS/Office/Ver");
  script_require_ports(139, 445);
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

# Variable Initialization
offVer = "";
path  = "";
fileVer = "";

## MS Office 2013
offVer = get_kb_item("MS/Office/Ver");
if(!offVer){
  exit(0);
}

## Get Office File Path
path = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
                            item:"CommonFilesDir");
if(!path){
  exit(0);
}

## Office 2013
if(offVer =~ "^15.*")
{
  filePath = path + "\Microsoft Shared\OFFICE15";
  fileVer = fetch_file_version(sysPath:filePath, file_name:"Msores.dll");
  if(fileVer)
  {
    ## Grep for Msores.dll version < 15.0.4551.1001
    if(version_in_range(version:fileVer, test_version:"15.0", test_version2:"15.0.4551.1000"))
    {
      security_message(0);
      exit(0);
    }
  }
}
