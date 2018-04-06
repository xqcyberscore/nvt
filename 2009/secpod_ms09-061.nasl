###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms09-061.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Microsoft .NET Common Language Runtime Remote Code Execution Vulnerability (974378)
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Updated By: Madhuri D <dmadhuri@secpod.com> on 2010-11-24
#  - To detect file version 'mscorlib.dll' on vista and win 2008
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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

tag_impact = "Remote attackers could execute arbitrary code and compromise the affected
  system.
  Impact Level: System.";
tag_affected = "Microsoft .NET Framework 3.5/SP 1
  Microsoft .NET Framework 1.1 SP 1
  Microsoft .NET Framework 2.0 SP 1/SP 2";
tag_insight = "- An unspecified error can be exploited to obtain a managed pointer to stack
    memory which can be used to overwrite data at that stack location.
  - An error in the type equality check can be exploited to cast an object of
    one type into another type.
  - An error when handling interfaces can be exploited by malicious .NET or
    Silverlight applications to corrupt memory.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link.
  http://www.microsoft.com/technet/security/bulletin/ms09-061.mspx";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS09-061.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900964");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-10-15 17:04:00 +0200 (Thu, 15 Oct 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-0090", "CVE-2009-0091", "CVE-2009-2497");
  script_bugtraq_id(36611, 36612, 36618);
  script_name("Microsoft .NET Common Language Runtime Code Execution Vulnerability (974378)");


  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/37006/");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/2896");
  script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/bulletin/MS09-061.mspx");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(xp:4, win2k:5, win2003:3, winVista:3, win2008:3) <= 0){
  exit(0);
}

# MS09-061 Hotfix check
if((hotfix_missing(name:"953297") == 0) || (hotfix_missing(name:"953298") == 0)||
   (hotfix_missing(name:"953300") == 0) || (hotfix_missing(name:"974417") == 0)||
   (hotfix_missing(name:"974468") == 0) || (hotfix_missing(name:"974292") == 0)||
   (hotfix_missing(name:"974467") == 0) || (hotfix_missing(name:"974291") == 0)||
   (hotfix_missing(name:"974469") == 0) || (hotfix_missing(name:"974470") == 0)){
    exit(0);
}

key  = "SOFTWARE\Microsoft\Windows\CurrentVersion\SharedDlls\";
if(registry_key_exists(key:key)) 
{
# Get the location of mscorlib.dll
foreach dllPath (registry_enum_values(key:key))
{
  if((".NET" >< dllPath) && ("\mscorlib.dll" >< dllPath))
  {
    share = ereg_replace(pattern:"([a-zA-Z]):.*", replace:"\1$", string:dllPath);
    file = ereg_replace(pattern:"[a-zA-Z]:(.*)", replace:"\1", string:dllPath);

    # Get the version of mscorlib.dll
    dllVer = GetVer(file:file, share:toupper(share));
    if(!isnull(dllVer))
    {
      # Check for mscorlib.dll < 1.1.4322.2433, 2.0.50727.1873, 2.0.50727.3603,
      # 2.0.50727.4062
      if(version_in_range(version:dllVer, test_version:"1.1.4322.2000",test_version2:"1.1.4322.2442") ||
         version_in_range(version:dllVer, test_version:"2.0.50727.1000",test_version2:"2.0.50727.1872")||
         version_in_range(version:dllVer, test_version:"2.0.50727.3000",test_version2:"2.0.50727.3602")||
         version_in_range(version:dllVer, test_version:"2.0.50727.4000",test_version2:"2.0.50727.4061"))
      {
        security_message(0);
        exit(0);
      }
    }
  }
}
}

key = "SOFTWARE\Microsoft\ASP.NET\";
if(!registry_key_exists(key:key)){
  exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  path = registry_get_sz(key:key + item, item:"Path");
  if("\Microsoft.NET\Framework" >< path)
  {
    path =  path + "\mscorlib.dll";
    share = ereg_replace(pattern:"([a-zA-Z]):.*", replace:"\1$", string:path);
    file = ereg_replace(pattern:"[a-zA-Z]:(.*)", replace:"\1", string:path);

    # Get the version of mscorlib.dll
    Ver = GetVer(file:file, share:share);
    if(!Ver){
      exit (0);
    }
  }
}

## Windows vista
if(hotfix_check_sp(winVista:3) > 0)
{
  ## Check for the version mscorlib.dll
  if(version_in_range(version:Ver, test_version:"1.1.4322.2000", test_version2:"1.1.4322.2442") ||
     version_in_range(version:Ver, test_version:"2.0.50727.1000", test_version2:"2.0.50727.1002") ||
     version_in_range(version:Ver, test_version:"2.0.50727.1800", test_version2:"2.0.50727.1872") ||
     version_in_range(version:Ver, test_version:"2.0.50727.3000", test_version2:"2.0.50727.3602") ||
     version_in_range(version:Ver, test_version:"2.0.50727.4000", test_version2:"2.0.50727.4199"))
  {
    security_message(0);
    exit(0);
  }
}

## Windows 2008 server
if(hotfix_check_sp(win2008:3) > 0)
{
  ## Check for the version mscorlib.dll
  if(version_in_range(version:Ver, test_version:"1.1.4322.2000", test_version2:"1.1.4322.2442") ||
     version_in_range(version:Ver, test_version:"2.0.50727.1000", test_version2:"2.0.50727.1872") ||
     version_in_range(version:Ver, test_version:"2.0.50727.4000", test_version2:"2.0.50727.4061") ||
     version_in_range(version:Ver, test_version:"2.0.50727.4000", test_version2:"2.0.50727.4199"))
  {
    security_message(0);
    exit(0);
  }
}

