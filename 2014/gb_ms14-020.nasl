###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms14-020.nasl 9354 2018-04-06 07:15:32Z cfischer $
#
# Microsoft Office Publisher Remote Code Execution Vulnerability (2950145)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804422");
  script_version("$Revision: 9354 $");
  script_cve_id("CVE-2014-1759");
  script_bugtraq_id(66622);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:15:32 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2014-04-09 07:45:13 +0530 (Wed, 09 Apr 2014)");
  script_tag(name:"solution_type", value: "VendorFix");
  script_name("Microsoft Office Publisher Remote Code Execution Vulnerability (2950145)");

  tag_summary =
"This host is missing an important security update according to Microsoft
Bulletin MS14-020.";

  tag_vuldetect =
"Get the vulnerable file version and check appropriate patch is applied
or not.";

  tag_insight =
"The flaw is due to an error within pubconv.dll. This can be exploited to
corrupt memory and cause an invalid value to be dereferenced as a pointer
via a specially crafted Publisher file.";

  tag_impact =
"Successful exploitation will allow attackers to bypass certain security
features.

Impact Level: System/Application";

  tag_affected =
"Microsoft Publisher 2003 Service Pack 3 and prior
Microsoft Publisher 2007 Service Pack 3 and prior";

  tag_solution =
"Run Windows Update and update the listed hotfixes or download and
update mentioned hotfixes in the advisory from the below link,
https://technet.microsoft.com/en-us/security/bulletin/ms14-020";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"registry");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/57652");
  script_xref(name : "URL" , value : "https://support.microsoft.com/kb/2878299");
  script_xref(name : "URL" , value : "https://support.microsoft.com/kb/2817565");
  script_xref(name : "URL" , value : "http://technet.microsoft.com/en-us/security/bulletin/ms14-020");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl",
                      "gb_smb_windows_detect.nasl");
  script_mandatory_keys("SMB/Office/Publisher/Version");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

## Variable Initialization
pubVer = "";
offVer = "";
pubFile = "";

## Grep for Office Publisher Version from KB
offVer = get_kb_item("SMB/Office/Publisher/Version");
if(offVer && offVer =~ "^(11|12)\..*")
{

  # Office Publisher
  pubFile = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion" +
                              "\App Paths\MSPUB.EXE", item:"Path");
  if(pubFile)
  {
    pubVer = fetch_file_version(sysPath:pubFile, file_name:"\Pubconv.dll");
    if(pubVer)
    {
       ## Grep for Pubconv.dll version 11 < 11.0.8410, 12 < 12.0.6694.5000
       if(version_in_range(version:pubVer, test_version:"11.0",test_version2:"11.0.8409") ||
          version_in_range(version:pubVer, test_version:"12.0",test_version2:"12.0.6694.4999"))
       {
         security_message(0);
         exit(0);
       }
    }
  }
}
