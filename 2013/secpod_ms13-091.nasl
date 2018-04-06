###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms13-091.nasl 9353 2018-04-06 07:14:20Z cfischer $
#
# Microsoft Office Remote Code Execution Vulnerabilities (2885093)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.903414");
  script_version("$Revision: 9353 $");
  script_cve_id("CVE-2013-0082", "CVE-2013-1324", "CVE-2013-1325");
  script_bugtraq_id(63559, 63569, 63570);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2013-11-13 15:08:45 +0530 (Wed, 13 Nov 2013)");
  script_name("Microsoft Office Remote Code Execution Vulnerabilities (2885093)");

  tag_summary =
"This host is missing an important security update according to
Microsoft Bulletin MS13-091.";

  tag_vuldetect =
"Get the vulnerable file version and check appropriate patch is applied
or not.";

  tag_insight =
"Flaws are due to an error when parsing WordPerfect documents files (.wpd).";

  tag_impact =
"Successful exploitation will allow remote attackers to corrupt memory, cause
a buffer overflow and execution the arbitrary code.

Impact Level: System/Application ";

  tag_affected =
"Microsoft Office 2013
Microsoft Office 2003 Service Pack 3 and prior
Microsoft Office 2007 Service Pack 3 and prior
Microsoft Office 2010 Service Pack 1  and prior";

  tag_solution =
"Run Windows Update and update the listed hotfixes or download and update
mentioned hotfixes in the advisory from the below link,
https://technet.microsoft.com/en-us/security/bulletin/ms13-091";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/55539");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2760494");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2760781");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2768005");
  script_xref(name : "URL" , value : "http://technet.microsoft.com/en-us/security/bulletin/ms13-091");
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

## MS Office 2003
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

## Office 2003 text converters
if(offVer =~ "^11.*")
{
  filePath = path + "\Microsoft Shared\TextConv";
  fileVer = fetch_file_version(sysPath:filePath, file_name:"msconv97.dll");
  if(fileVer)
  {
    ## Grep for Msconv97.dll version < 2003.1100.8327
    if(version_in_range(version:fileVer, test_version:"2003", test_version2:"2003.1100.8326"))
    {
      security_message(0);
      exit(0);
    }
  }
}

## Microsoft Office 2013 (file formats)
if(offVer =~ "^(12|14|15)\..*")
{
  filePath = path + "\Microsoft Shared\TextConv";
  ##
  fileVer = fetch_file_version(sysPath:filePath, file_name:"Wpft532.cnv");
  if(fileVer)
  {
    ## Microsoft Office 2007 File Formats
    ## Microsoft Office 2013 (file formats)
    ## Microsoft Office 2010 (file format converters)
    if(version_in_range(version:fileVer, test_version:"2012", test_version2:"2012.1500.4525.0999")||
       version_in_range(version:fileVer, test_version:"2010", test_version2:"2010.1400.7011.0999") ||
       version_in_range(version:fileVer, test_version:"2006", test_version2:"2006.1200.6676.4999"))
    {
      security_message(0);
      exit(0);
    }
  }
}
