###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms14-023.nasl 9354 2018-04-06 07:15:32Z cfischer $
#
# Microsoft Office Remote Code Execution Vulnerabilities (2961037)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
#  Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.804450");
  script_version("$Revision: 9354 $");
  script_cve_id("CVE-2014-1756", "CVE-2014-1808");
  script_bugtraq_id(67274, 67279);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:15:32 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2014-05-14 12:01:21 +0530 (Wed, 14 May 2014)");
  script_tag(name:"solution_type", value: "VendorFix");
  script_name("Microsoft Office Remote Code Execution Vulnerabilities (2961037)");

  tag_summary =
"This host is missing an important security update according to
Microsoft Bulletin MS14-023.";

  tag_vuldetect =
"Get the vulnerable file version and check appropriate patch is applied
or not.";

  tag_insight =
"- The flaw is due to the Grammar Checker feature for Chinese (Simplified)
   loading libraries in an insecure manner.
 - An error when handling a certain response can be exploited to gain knowledge
   of access tokens used for authentication of the current user.";

  tag_impact =
"Successful exploitation will allow remote attackers to execute the arbitrary
code.

Impact Level: System/Application";

  tag_affected =
"Microsoft Office 2007 Service Pack 3 (proofing tools)
Microsoft Office 2010 Service Pack 2 (proofing tools) and prior
Microsoft Office 2013 Service Pack 1 (proofing tools) and prior ";

  tag_solution =
"Run Windows Update and update the listed hotfixes or download and update
mentioned hotfixes in the advisory from the below link,
https://technet.microsoft.com/en-us/security/bulletin/ms14-023";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name:"qod_type", value:"registry");

  script_xref(name : "URL" , value : "https://support.microsoft.com/kb/2767772");
  script_xref(name : "URL" , value : "https://support.microsoft.com/kb/2878284");
  script_xref(name : "URL" , value : "https://support.microsoft.com/kb/2878316");
  script_xref(name : "URL" , value : "https://technet.microsoft.com/en-us/security/bulletin/ms14-023");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
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
    ## Grep for Msores.dll version < 15.0.4615.1000
    if(version_in_range(version:fileVer, test_version:"15.0", test_version2:"15.0.4615.999"))
    {
      security_message(0);
      exit(0);
    }
  }
}


key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if(!registry_key_exists(key:key)) {
  exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  appName = registry_get_sz(key:key+item, item:"DisplayName");
  if("Microsoft Office Proofing" >< appName)
  {
    ptPath = registry_get_sz(key:key+item, item:"InstallLocation");
    if(ptPath)
    {
      ## Iterate over the office version
      foreach offver (make_list("OFFICE12", "OFFICE14", "OFFICE15"))
      {
        ## Iterate over each language pack
        foreach langPack (make_list("1025", "1030", "1031", "1033", "3082", "1040", "1041",
                                    "1042", "1044", "1046", "1049", "2052", "1028"))
        {
          ## construct the path
          ptPath1 = ptPath + offver + "\PROOF\" +  langPack ;

          ## Get Version from Msgr3en.dll file version
          exeVer = fetch_file_version(sysPath:ptPath1, file_name:"\Msgr3en.dll");
          if(exeVer)
          {
            if(("1025" >< ptPath1 || "1030" ><  ptPath1 ||"1040" >< ptPath1 ||
                "1044" >< ptPath1 || "1046" >< ptPath1 ||  "1049" >< ptPath1)
                && ("OFFICE15" >< ptPath1))
            {

              ## Check for version
              if(version_in_range(version:exeVer, test_version:"15.0", test_version2:"15.0.4615.999"))
              {
                security_message(0);
                exit(0);
              }
            }

            if(("1033" >< ptPath1 || "3082" ><  ptPath1 ||"1041" >< ptPath1 ||
              "1042" >< ptPath1 || "1028" >< ptPath1) && ("OFFICE15" >< ptPath1))
            {
              if(version_in_range(version:exeVer, test_version:"15.0", test_version2:"15.0.4454.999"))
              {
                security_message(0);
                exit(0);
              }
            }

            if("1031" >< ptPath1  && "OFFICE15" >< ptPath1)
            {
              if(version_in_range(version:exeVer, test_version:"15.0", test_version2:"15.0.4611.999"))
              {
                security_message(0);
                exit(0);
              }
            }

            if("2052" >< ptPath1  && "OFFICE12" >!<  ptPath1)
            {
              if(version_in_range(version:exeVer, test_version:"3.0", test_version2:"3.0.1710.0"))
              {
                security_message(0);
                exit(0);
              }
            }

            if("2052" >< ptPath1  && "OFFICE12" ><  ptPath1)
            {
              if(version_in_range(version:exeVer, test_version:"3.0", test_version2:"3.0.1711.1199"))
              {
                security_message(0);
                exit(0);
              }
            }
          }
        }
      }
    }
  }
}
