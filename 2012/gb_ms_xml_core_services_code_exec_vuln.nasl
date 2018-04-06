###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_xml_core_services_code_exec_vuln.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# Microsoft XML Core Services Remote Code Execution Vulnerability (2719615)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802864");
  script_version("$Revision: 9352 $");
  script_cve_id("CVE-2012-1889");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-06-14 12:09:11 +0530 (Thu, 14 Jun 2012)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft XML Core Services Remote Code Execution Vulnerability (2719615)");

  script_tag(name: "summary" , value:"This host is installed with Microsoft XML Core Services and
  is prone to remote code execution vulnerability.");

  script_tag(name: "vuldetect" , value:"Get the vulnerable file version and check
  appropriate patch is applied or not.");

  script_tag(name: "insight" , value:"Microsoft XML Core Services attempts to access
  an object in memory that has not been initialized, which allows  an attacker to
  corrupt memory.");

  script_tag(name: "impact" , value:"Successful exploitation could allow remote
  attackers to execute arbitrary code as the logged-on user.

  Impact Level: System/Application");

  script_tag(name: "affected" , value:"Microsoft Expression Web 2
  Microsoft Office Word Viewer
  Microsoft Office Compatibility
  Microsoft Office 2003 Service Pack 3 and prior
  Microsoft Office 2007 Service Pack 3 and prior
  Microsoft Expression Web Service Pack 1 and prior
  Microsoft Groove Server 2007 Service Pack 3 and prior
  Microsoft SharePoint Server 2007 Service Pack 3 and prior
  Microsoft Windows XP x32 Edition Service Pack 3 and prior
  Microsoft Windows XP x64 Edition Service Pack 2 and prior
  Microsoft Windows 7 x32/x64 Edition Service Pack 1 and prior
  Microsoft Windows 2003 x32/x64 Edition Service Pack 2 and prior
  Microsoft Windows Vista x32/x64 Edition Service Pack 2 and prior
  Microsoft Windows Server 2008 R2 x64 Edition Service Pack 1 and prior
  Microsoft Windows Server 2008 x32/x64 Edition Service Pack 2 and prior");

  script_tag(name: "solution" , value:"Apply the Patch from below links,
  http://technet.microsoft.com/en-us/security/advisory/2719615
  http://technet.microsoft.com/en-us/security/bulletin/ms12-043");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/49456");
  script_xref(name : "URL" , value : "http://securitytracker.com/id/1027157");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2719615");
  script_xref(name : "URL" , value : "http://technet.microsoft.com/en-us/security/advisory/2719615");
  script_xref(name : "URL" , value : "http://technet.microsoft.com/en-us/security/bulletin/ms12-043");

  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl",
                      "secpod_office_products_version_900032.nasl",
                      "gb_ms_sharepoint_sever_n_foundation_detect.nasl",
                      "gb_ms_expression_web_detect.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

## Variables Initialization
sysPath = "";
dllVer3 = "";
dllVer4 = "";
dllVer5 = "";
dllVer6 = "";

## Check for OS and Service Pack
if(hotfix_check_sp(xp:4, xpx64:3, win2003:3, win2003x64:3, winVista:3, win7:2,
                   win7x64:2, win2008:3, win2008r2:2) <= 0)
{
  exit(0);
}

## Get System Path
sysPath = smb_get_systemroot();
if(! sysPath){
   exit(0);
}

## Get Version from Msxml3.dll file
dllVer3 = fetch_file_version(sysPath, file_name:"system32\Msxml3.dll");

## Check for XML Core Services 3.0
if(dllVer3)
{
  ## Windows XP
  if(hotfix_check_sp(xp:4) > 0)
  {
    ## Check for Msxml3.dll version before 8.100.1053.0
    if(version_is_less(version:dllVer3, test_version:"8.100.1053.0"))
    {
      Vulnerable_range = "Version Less than - 8.100.1053.0";
      VULN = TRUE ;
    }
  }

  ## Windows 2003 x86, Windows XP x64 and Windows 2003 x64
  else if(hotfix_check_sp(win2003:3, xpx64:3, win2003x64:3) > 0)
  {
     ## Check for Msxml3.dll version
     if(version_is_less(version:dllVer3, test_version:"8.100.1052.0"))
     {
       Vulnerable_range = "Version Less than - 8.100.1052.0";
       VULN = TRUE ;
     }
  }

  ## Windows Vista and Windows Server 2008
  ## Currently not supporting for Vista and Windows Server 2008 64 bit
  else if(hotfix_check_sp(winVista:3, win2008:3) > 0)
  {
    ## Check for Msxml3.dll version
    if(version_is_less(version:dllVer3, test_version:"8.100.5005.0"))
    {
      Vulnerable_range = "Version Less than - 8.100.5005.0";
      VULN = TRUE ;
    }
  }

  ## Windows 7
  else if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
  {
    ## Check for Msxml3.dll version
    if(version_is_less(version:dllVer3, test_version:"8.110.7600.17036")){
      Vulnerable_range = "Version Less than - 8.110.7600.17036";
      VULN = TRUE ;
    }
    else if(version_in_range(version:dllVer3, test_version:"8.110.7600.20000", test_version2:"8.110.7600.21226")){
      Vulnerable_range = "8.110.7600.20000 - 8.110.7600.21226";
      VULN = TRUE ;
    }
    else if(version_in_range(version:dllVer3, test_version:"8.110.7601.17000", test_version2:"8.110.7601.17856")){
      Vulnerable_range = "8.110.7601.17000 - 8.110.7601.17856";
      VULN = TRUE ; 
    }
    else if(version_in_range(version:dllVer3, test_version:"8.110.7601.21000", test_version2:"8.110.7601.22011"))
    {
      Vulnerable_range = "8.110.7601.21000 - 8.110.7601.22011";
      VULN = TRUE ;
    }
  }
  dllVer = dllVer3 ;
  location = sysPath + "\system32\Msxml3.dll";
}

## Get Version from Msxml4.dll file
dllVer4 = fetch_file_version(sysPath, file_name:"system32\Msxml4.dll");

## Check for XML Core Services 4.0
if(dllVer4)
{
  if(version_is_less(version:dllVer4, test_version:"4.30.2114.0"))
  {
    dllVer = dllVer4 ;
    Vulnerable_range = "Version Less than - 4.30.2114.0";
    location = sysPath + "\system32\Msxml4.dll";
    VULN = TRUE ;
  }
}

## Get Version from Msxml6.dll file
dllVer6 = fetch_file_version(sysPath, file_name:"system32\Msxml6.dll");

## Check for XML Core Services 6.0
dllVer6 = fetch_file_version(sysPath, file_name:"system32\Msxml6.dll");
if(dllVer6)
{
  ## Windows XP
  if(hotfix_check_sp(xp:4) > 0)
  {
    ## Check for Msxml6.dll version before 6.20.2501.0
    if(version_is_less(version:dllVer6, test_version:"6.20.2501.0"))
    {
      Vulnerable_range = "Version Less than - 6.20.2501.0";
      VULN = TRUE ;
    }
  }

  ## Windows 2003 x86, Windows XP x64 and Windows 2003 x64
  else if(hotfix_check_sp(win2003:3, xpx64:3, win2003x64:3) > 0)
  {
    ## Check for Msxml6.dll version before 6.20.2012.0
    if(version_is_less(version:dllVer6, test_version:"6.20.2012.0"))
    {
      Vulnerable_range = "Version Less than - 6.20.2012.0";
      VULN = TRUE ;
    }
  }

  ## Windows Vista and Windows Server 2008
  ## Currently not supporting for Vista and Windows Server 2008 64 bit
  else if(hotfix_check_sp(winVista:3, win2008:3) > 0)
  {
    ## Check for Msxml6.dll version
    if(version_is_less(version:dllVer6, test_version:"6.20.5005.0"))
    {
      Vulnerable_range = "Version Less than - 6.20.5005.0";
      VULN = TRUE ;
    }
  }

  ## Windows 7
  else if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
  {
    ## Check for Msxml3.dll version
    if(version_is_less(version:dllVer6, test_version:"6.30.7600.17036")){
      Vulnerable_range = "Version Less than - 6.30.7600.17036";
      VULN = TRUE ;
    }
    else if(version_in_range(version:dllVer6, test_version:"6.30.7600.20000", test_version2:"6.30.7600.21226")){
      Vulnerable_range = "6.30.7600.20000 - 6.30.7600.21226";
      VULN = TRUE ;
    }
    else if(version_in_range(version:dllVer6, test_version:"6.30.7601.17000", test_version2:"6.30.7601.17856")){
      Vulnerable_range = "6.30.7601.17000 - 6.30.7601.17856";
      VULN = TRUE ;
    }
    else if(version_in_range(version:dllVer6, test_version:"6.30.7601.21000", test_version2:"6.30.7601.22011")){
      Vulnerable_range = "6.30.7601.21000 - 6.30.7601.22011";
      VULN = TRUE ;
    }
  }

  dllVer = dllVer6;
  location = sysPath + "\system32\Msxml6.dll";
}

if(VULN)
{
  report = 'File checked:     ' + location + '\n' +
           'File version:     ' + dllVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range + '\n' ;
  security_message(data:report);
  exit(0);
}

## Check for XML Core Services 5.0
## Check for Office 2003, 2007, Word Viewer, Compatibility Pack,
## Groove server 2007 , Sharepoint Server 2007
if(get_kb_item("MS/Office/Ver") =~ "^[11|12].*" ||
   get_kb_item("SMB/Office/Word/Version") ||
   get_kb_item("SMB/Office/WordCnv/Version")||
   get_kb_item("SMB/Office/Groove/Version") =~ "^12"||
   get_kb_item("MS/SharePoint/Server/Ver") =~ "^12" ||
   get_kb_item("MS/Expression-Web/Ver") =~ "^12")
{
  ## Get System CommonFiles Dir Path
  sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
                          item:"CommonFilesDir");
  if(! sysPath){
    exit(0);
  }

  ## Get Version from office patch
  foreach ver (make_list("OFFICE11", "OFFICE12"))
  {
    ## Get Version from Msxml5.dll
    sysPath = sysPath + "\Microsoft Shared\" + ver ;

    ## Get Version from Msxml4.dll file
    dllVer5 = fetch_file_version(sysPath, file_name:"Msxml5.dll");

    if(! dllVer5){
     continue;
    }

    ## Check for Msxml6.dll version
    if(version_is_less(version:dllVer5, test_version:"5.20.1096.0"))
    {
      report = 'File checked:     ' + sysPath + "\system32\Msxml5.dll" + '\n' +
               'File version:     ' + dllVer5  + '\n' +
               'Vulnerable range: Version Less than - 5.20.1096.0 \n' ;
      security_message(data:report);
      exit(0);
    }
  }
}
