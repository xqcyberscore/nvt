###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms11-086.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Microsoft Windows Active Directory LDAPS Authentication Bypass Vulnerability (2630837)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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

tag_impact = "Successful exploitation will allow the remote attackers to use revoked
  certificate to authenticate to the Active Directory domain and gain
  access to network resources or run code under the privileges of a
  specific authorized user with which the certificate is associated.
  Impact Level: System/Application.";
tag_affected = "Microsoft Windows 7 Service Pack 1 and prior
  Microsoft Windows XP Service Pack 3 and prior
  Microsoft Windows Vista Service Pack 2 and prior
  Microsoft Windows Server 2003 Service Pack 2 and prior
  Microsoft Windows Server 2008 Service Pack 2 and prior";
tag_insight = "The flaw is due to an error in Active Directory when configured to
  use LDAP over SSL. It fails to validate the revocation status of an SSL
  certificate against the CRL (Certificate Revocation List) associated with
  the domain account. This can be exploited to authenticate to the Active
  Directory domain using a revoked certificate.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://www.microsoft.com/technet/security/bulletin/ms1-086.mspx";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS11-086.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902487");
  script_version("$Revision: 9351 $");
  script_cve_id("CVE-2011-2014");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-11-09 12:52:09 +0530 (Wed, 09 Nov 2011)");
  script_name("Microsoft Windows Active Directory LDAPS Authentication Bypass Vulnerability (2630837)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/46755/");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2601626");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2616310");
  script_xref(name : "URL" , value : "http://technet.microsoft.com/en-us/security/bulletin/ms11-086");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

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

if(hotfix_check_sp(xp:4, win2003:3, winVista:3, win2008:3, win7:2) <= 0){
  exit(0);
}

## Get System Path
sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

# Active Directory
if((hotfix_missing(name:"2601626") == 1) &&
   registry_key_exists(key:"SYSTEM\CurrentControlSet\Services\NTDS\Performance"))
{
  ntdsaVer = fetch_file_version(sysPath, file_name:"system32\Ntdsa.dll");
  if(ntdsaVer != NULL)
  {
    # Windows 2K3
    if(hotfix_check_sp(win2003:3) > 0)
    {
      SP = get_kb_item("SMB/Win2003/ServicePack");
      if("Service Pack 2" >< SP)
      {
        # Check for Ntdsa.dll version < 5.2.3790.4910
        if(version_is_less(version:ntdsaVer, test_version:"5.2.3790.4910")){
            security_message(0);
        }
          exit(0);
      }
        security_message(0);
    }
  }
}

# Active Directory Application Mode
if((hotfix_missing(name:"2616310") == 1) &&
   registry_key_exists(key:"SYSTEM\CurrentControlSet\Services\ADAM\Linkage"))
{
  # Get the version of Active Directory Application Mode
  adamdsaVer = fetch_file_version(sysPath, file_name:"ADAM\Adamdsa.dll");
  if(adamdsaVer != NULL)
  {
    # Windows XP/2K3
    if(hotfix_check_sp(xp:4, win2003:3) > 0)
    {
      XPSP = get_kb_item("SMB/WinXP/ServicePack");
      k3SP = get_kb_item("SMB/Win2003/ServicePack");
      if(("Service Pack 3" >< XPSP) || ("Service Pack 2" >< k3SP))
      {
        # Check for Adamdsa.dll version < 1.1.3790.4905
        if(version_is_less(version:adamdsaVer, test_version:"1.1.3790.4905")){
           security_message(0);
        }
        exit(0);
      }
        security_message(0);
    }
  }
}

## Checking the Hotfix for Active Directory Lightweight Directory Service (AD LDS)
if((hotfix_missing(name:"2601626") == 0)){
  exit(0);
}

## AD LAS For Windows 7, vista and 2008 server
## Get the version for Ntdsai.dll
dllVer = fetch_file_version(sysPath, file_name:"system32\Ntdsai.dll");
if(!dllVer){
  exit(0);
}

## Windows Vista and Windows Server 2008
else if(hotfix_check_sp(winVista:3, win2008:3) > 0)
{
  SP = get_kb_item("SMB/WinVista/ServicePack");

  if(!SP) {
    SP = get_kb_item("SMB/Win2008/ServicePack");
  }

  if("Service Pack 2" >< SP)
  {
    ## Check for Ntdsai.dll version
    if(version_in_range(version:dllVer, test_version:"6.0.6002.18000", test_version2:"6.0.6002.18507")||
       version_in_range(version:dllVer, test_version:"6.0.6002.22000", test_version2:"6.0.6002.22704")){
      security_message(0);
    }
    exit(0);
  }
  security_message(0);
}

## Windows 7
else if(hotfix_check_sp(win7:2) > 0)
{
  ## Grep for Ntdsai.dll version
  if(version_is_less(version:dllVer, test_version:"6.1.7600.16871") ||
     version_in_range(version:dllVer, test_version:"6.1.7600.21000", test_version2:"6.1.7600.21034") ||
     version_in_range(version:dllVer, test_version:"6.1.7601.17000", test_version2:"6.1.7601.17675") ||
     version_in_range(version:dllVer, test_version:"6.1.7601.21000", test_version2:"6.1.7601.21801")){
    security_message(0);
  }
}
