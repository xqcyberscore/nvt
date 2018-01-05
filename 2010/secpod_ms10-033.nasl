###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms10-033.nasl 8276 2018-01-03 12:29:18Z asteins $
#
# Microsoft Media Decompression Remote Code Execution Vulnerability (979902)
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
#  
# Updated By: Madhuri D <dmadhuri@secpod.com> on 2010-11-16
#       - To detect required file versions on vista, win 2008 and win 7
#
# Copyright (c) 2010 SecPod, http://www.secpod.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900246");
  script_version("$Revision: 8276 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-03 13:29:18 +0100 (Wed, 03 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-06-09 17:19:57 +0200 (Wed, 09 Jun 2010)");
  script_bugtraq_id(40432, 40464);
  script_cve_id("CVE-2010-1879", "CVE-2010-1880");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Microsoft Media Decompression Remote Code Execution Vulnerability (979902)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/40058");
  script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/bulletin/ms10-033.mspx");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name : "impact" , value : "Successful exploitation will allow remote attackers to execute arbitrary
  code.
  Impact Level: System");
  script_tag(name : "insight" , value : "An unspecified error exists while processing media files with a specially
  crafted compression data. An attacker can exploit this vulnerability by
  tricking a user to open a specially crafted media file.");
  script_tag(name : "summary" , value : "This host is missing a critical security update according to
  Microsoft Bulletin MS10-033.");
  script_tag(name : "solution" , value : "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://www.microsoft.com/technet/security/bulletin/ms10-033.mspx");
  script_tag(name : "affected" , value : "DirectX, Windows Media Encoder 9 and COM component on,
  Micorsoft Windows 7
  Microsoft Windows 2000 SP4
  Microsoft Windows XP Service Pack 3 and prior
  Microsoft Windows 2K3 Service Pack 2 and prior
  Microsoft Windows Vista Service Pack 1/2 and prior.
  Microsoft Windows Server 2008 Service Pack 1/2 and prior.

  Windows Media Format Runtime 9 on,
  Microsoft Windows 2000 SP4
  Microsoft Windows XP Service Pack 3 and prior

  Windows Media Format Runtime 9.5 on,
  Microsoft Windows XP Service Pack 3 and prior
  Microsoft Windows 2K3 Service Pack 2 and prior

  Windows Media Format Runtime 11 on,
  Microsoft Windows XP Service Pack 3 and prior");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");


## OS with Hotfix Check
if(hotfix_check_sp(win2k:5, xp:4, win2003:3, winVista:3, win7:1, win2008:3) <= 0){
  exit(0);
}

# MS10-033 Hotfix check
if(hotfix_missing(name:"975562") == 0 || hotfix_missing(name:"978695") == 0 ||
   hotfix_missing(name:"979332") == 0 || hotfix_missing(name:"979482") == 0 ){
  exit(0);
}

## Windows Media Encoder 9 vulnerability
wme9Installed = registry_key_exists(key:"SOFTWARE\Microsoft\Windows" +
                 "\CurrentVersion\Uninstall\Windows Media Encoder 9");
if(wme9Installed)
{
  wmekey = "SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\wmenc.exe";
  wmeitem = "Path";
  wmePath = registry_get_sz(key:wmekey, item:wmeitem);

  dllVer = fetch_file_version(sysPath:wmePath, file_name:"Wmenceng.dll");
  if(dllVer)
  {
    ## Check Wmenceng.dll version < 9.0.0.3369
    if(version_in_range(version:dllVer, test_version:"9.0",
                                        test_version2:"9.0.0.3368")){
      security_message(0);
      exit(0);
    }
  }
}

## Get System32 Path
system32Path = smb_get_system32root();
if(!system32Path){
  exit(0);
}

## Windows 2000
if(hotfix_check_sp(win2k:5) > 0)
{

  ## Check for Asycfilt.dll COM component vulnerability
  dllVer = fetch_file_version(sysPath:system32Path, file_name:"Asycfilt.dll");
  if(dllVer)
  {
      ## Check Asycfilt.dll version < 2.40.4534.0
      if(version_is_less(version:dllVer, test_version:"2.40.4534.0")){
        security_message(0);
        exit(0);
      }
  }

  ## Check for DirectX vulnerability
  directXver = registry_get_sz(key:"SOFTWARE\Microsoft\DirectX",
                               item:"Version");
  if(directXver =~ "^4\.09")
  {
    dllVer = fetch_file_version(sysPath:system32Path, file_name:"Quartz.dll");
    if(dllVer)
    {
      ## Grep Quartz.dll version < 6.5.1.914
      if(version_in_range(version:dllVer, test_version:"6.5",
                                          test_version2:"6.5.1.913")){
        security_message(0);
        exit(0);
      }
    }
  }

  ## Check for Media Format Runtime vulnerability
  dllVer = fetch_file_version(sysPath:system32Path, file_name:"Wmvcore.dll");
  if(dllVer)
  {
      ## Check Asycfilt.dll version from 9.0  < 9.0.0.3369
      if(version_in_range(version:dllVer, test_version:"9.0",
                                          test_version2:"9.0.0.3368")){
        security_message(0);
        exit(0);
      }
  }
}

## Windows XP
else if(hotfix_check_sp(xp:4) > 0)
{
  SP = get_kb_item("SMB/WinXP/ServicePack");

  ## Check for Asycfilt.dll COM component vulnerability
  dllVer = fetch_file_version(sysPath:system32Path, file_name:"Asycfilt.dll");
  if(dllVer)
  {
    if("Service Pack 2" >< SP)
    {
      ## Check Asycfilt.dll version < 5.1.2600.3680
      if(version_is_less(version:dllVer, test_version:"5.1.2600.3680")){
        security_message(0);
        exit(0);
      }
    }
    else if("Service Pack 3" >< SP)
    {
      ## Check Asycfilt.dll version < 5.1.2600.5949
      if(version_is_less(version:dllVer, test_version:"5.1.2600.5949")){
        security_message(0);
        exit(0);
      }
    }
  }

  ## Check for DirectX vulnerability
  dllVer = fetch_file_version(sysPath:system32Path, file_name:"Quartz.dll");
  if(dllVer)
  {
    if("Service Pack 2" >< SP)
    {
      ## Grep Quartz.dll version 6.5  < 6.5.2600.3665
      if(version_in_range(version:dllVer, test_version:"6.5",
                                          test_version2:"6.5.2600.3664")){
        security_message(0);
        exit(0);
      }
    }
    else if("Service Pack 3" >< SP)
    {
      ## Grep Quartz.dll version 6.5 < 6.5.2600.5933
      if(version_in_range(version:dllVer, test_version:"6.5",
                                          test_version2:"6.5.2600.5932")){
        security_message(0);
        exit(0);
      }
    }
  }

  ## Check for Media Format Runtime vulnerability
  dllVer = fetch_file_version(sysPath:system32Path, file_name:"Wmvcore.dll");
  if(dllVer)
  {
    if("Service Pack 2" >< SP)
    {
      ## Check Asycfilt.dll version from 9.0  < 9.0.0.3272 and 10.0 < 10.0.0.3706
      ## and 11.0 < 11.0.5721.5275
      if(version_in_range(version:dllVer, test_version:"9.0", test_version2:"9.0.0.3271")||
         version_in_range(version:dllVer, test_version:"10.0", test_version2:"10.0.0.3705")||
         version_in_range(version:dllVer, test_version:"11.0", test_version2:"11.0.5721.5274")){
        security_message(0);
        exit(0);
      }
    }
    else if("Service Pack 3" >< SP)
    {
      ## Check Asycfilt.dll version from 9.0  < 9.0.0.4509 and 10.0 < 10.0.0.3706
      ## and 11.0 < 11.0.5721.5275
      if(version_in_range(version:dllVer, test_version:"9.0", test_version2:"9.0.0.4508")||
         version_in_range(version:dllVer, test_version:"10.0", test_version2:"10.0.0.3705")||
         version_in_range(version:dllVer, test_version:"11.0", test_version2:"11.0.5721.5274")){
        security_message(0);
        exit(0);
      }
    }
  }
}

## Windows 2003
if(hotfix_check_sp(win2003:3) > 0)
{
  SP = get_kb_item("SMB/Win2003/ServicePack");
  if("Service Pack 2" >< SP)
  {
    ## Check for Asycfilt.dll COM component vulnerability
    dllVer = fetch_file_version(sysPath:system32Path, file_name:"Asycfilt.dll");
    if(dllVer)
    {
      ## Check Asycfilt.dll version < 5.2.3790.4676
      if(version_is_less(version:dllVer, test_version:"5.2.3790.4676")){
        security_message(0);
        exit(0);
      }
    }

    ## Check for DirectX vulnerability
    directXver = registry_get_sz(key:"SOFTWARE\Microsoft\DirectX",
                                 item:"Version");
    if(directXver =~ "^4\.09")
    {
      dllVer = fetch_file_version(sysPath:system32Path, file_name:"Quartz.dll");
      if(dllVer)
      {
        ## Grep Quartz.dll version 6.5 < 6.5.3790.4660
        if(version_in_range(version:dllVer, test_version:"6.5",
                                            test_version2:"6.5.3790.4659")){
          security_message(0);
          exit(0);
        }
      }
    }

    ## Check for Media Format Runtime vulnerability
    dllVer = fetch_file_version(sysPath:system32Path, file_name:"Wmvcore.dll");
    if(dllVer)
    {
      ## Check Asycfilt.dll version from 10.0  < 10.0.0.4007
      if(version_in_range(version:dllVer, test_version:"10.0",
                                          test_version2:"10.0.0.4006")){
        security_message(0);
        exit(0);
      }
    }
  }
}

## Get System32 Path
system32Path = smb_get_system32root();
if(!system32Path){
  exit(0);
}

## Windows vista
if(hotfix_check_sp(winVista:3) > 0)
{
  ## Check for Asycfilt.dll COM component vulnerability
  dllVer = fetch_file_version(sysPath:system32Path, file_name:"Asycfilt.dll");
  if(dllVer)
  {
    SP = get_kb_item("SMB/WinVista/ServicePack");
    if("Service Pack 1" >< SP)
    {
      ## Check Asycfilt.dll version 
      if(version_is_less(version:dllVer, test_version:"6.0.6001.18454")){
          security_message(0);
      }
        exit(0);
    }
  
    if("Service Pack 2" >< SP)
    {
      # Grep for Asycfilt.dll version
      if(version_is_less(version:dllVer, test_version:"6.0.6002.18236")){
        security_message(0);
      }
     exit(0);
    }
    security_message(0);
  }

  ## Check for DirectX vulnerability
  directXver = registry_get_sz(key:"SOFTWARE\Microsoft\DirectX",
                               item:"Version");
  if(directXver =~ "^4\.09")
  {
    dllVer = fetch_file_version(sysPath:system32Path, file_name:"Quartz.dll");
    if(dllVer)
    {
      ## Grep Quartz.dll version 
      if(version_in_range(version:dllVer, test_version:"6.6", test_version2:"6.6.6001.18461")){
          security_message(0);
      }
        exit(0);
    }
  }
}

## Windows 2008 server
if(hotfix_check_sp(win2008:3) > 0)
{
  ## Check for Asycfilt.dll COM component vulnerability
  dllVer = fetch_file_version(sysPath:system32Path, file_name:"Asycfilt.dll");
  if(dllVer)
  {
    SP = get_kb_item("SMB/WinVista/ServicePack");
    if("Service Pack 1" >< SP)
    {
      ## Check Asycfilt.dll version 
      if(version_is_less(version:dllVer, test_version:"6.0.6001.18454")){
          security_message(0);
      }
        exit(0);
    }

    if("Service Pack 2" >< SP)
    {
      # Grep for Asycfilt.dll version
      if(version_is_less(version:dllVer, test_version:"6.0.6002.18236")){
        security_message(0);
      }
     exit(0);
    }
    security_message(0);
  }

  ## Check for DirectX vulnerability
  directXver = registry_get_sz(key:"SOFTWARE\Microsoft\DirectX",
                               item:"Version");
  if(directXver =~ "^4\.09")
  {
    dllVer = fetch_file_version(sysPath:system32Path, file_name:"Quartz.dll");
    if(dllVer)
    {
      ## Grep Quartz.dll version 
      if(version_in_range(version:dllVer, test_version:"6.6", test_version2:"6.6.6001.18460")){
          security_message(0);
      }
        exit(0);
    }
  }
}

## Windows 7
if(hotfix_check_sp(win7:1) > 0)
{
  dllVer = fetch_file_version(sysPath:system32Path, file_name:"Asycfilt.dll");
  if(dllVer)
  {
    # Grep for Asycfilt.dll version 
    if(version_is_less(version:dllVer, test_version:"6.1.7600.16544")){
     security_message(0);
    }
  }
}
