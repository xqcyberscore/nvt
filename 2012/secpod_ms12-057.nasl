###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms12-057.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# Microsoft Office Remote Code Execution Vulnerability (2731879)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2012 SecPod, http://www.secpod.com
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

tag_impact = "Successful exploitation could allow attackers to execute arbitrary code as
  the logged-on user.
  Impact Level: System/Application";
tag_affected = "Microsoft Office 2007 Service Pack 3 and prior
  Microsoft Office 2010 Service Pack 1 and prior";
tag_insight = "The flaw is due to an error when parsing CGM (Computer Graphics Metafile)
  files and can be exploited to corrupt memory via a specially crafted CGM file
  or Office document embedding CGM graphics content.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://technet.microsoft.com/en-us/security/bulletin/ms12-057";
tag_summary = "This host is missing an important security update according to
  Microsoft Bulletin MS12-057.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902920");
  script_version("$Revision: 9352 $");
  script_cve_id("CVE-2012-2524");
  script_bugtraq_id(54876);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-08-15 09:05:20 +0530 (Wed, 15 Aug 2012)");
  script_name("Microsoft Office Remote Code Execution Vulnerability (2731879)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/50251/");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2596615");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2596754");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2553260");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2589322");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2687501");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2687510");
  script_xref(name : "URL" , value : "http://technet.microsoft.com/en-us/security/bulletin/ms12-057");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_mandatory_keys("MS/Office/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");


## Variables Initialization
path = "";
ver = "";
dllVer = "";
fileVer = "";
offPath = "";
filePath = "";

## MS Office 2007, 2010
if(!get_kb_item("MS/Office/Ver") =~ "^[12|14].*"){
  exit(0);
}

## Get Office File Path
path = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
                            item:"CommonFilesDir");
if(!path){
  exit(0);
}

foreach ver (make_list("OFFICE12", "OFFICE14"))
{
  ## Get Version from Mso.dll
  offPath = path + "\Microsoft Shared\" + ver;
  dllVer = fetch_file_version(sysPath:offPath, file_name:"Mso.dll");

  if(dllVer)
  {
    ## Grep for Mso.dll versions
    if(version_in_range(version:dllVer, test_version:"12.0", test_version2:"12.0.6662.4999")||
       version_in_range(version:dllVer, test_version:"14.0", test_version2:"14.0.6129.4999"))
    {
      security_message(0);
      exit(0);
    }
  }
}

## Office system (MSCONV97) and Office 2010 (MSCONV)

filePath = path + "\Microsoft Shared\TextConv";
fileVer = fetch_file_version(sysPath:filePath, file_name:"msconv97.dll");
if(fileVer)
{
  ## Grep for Msconv97.dll version < 2006.1200.6662.5000, 2010.1400.6123.5000
  if(version_in_range(version:fileVer, test_version:"2006.0", test_version2:"2006.1200.6662.4999") ||
     version_in_range(version:fileVer, test_version:"2010.0", test_version2:"2010.1400.6123.4999")){
    security_message(0);
  }
}
