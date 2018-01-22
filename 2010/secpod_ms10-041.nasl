###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms10-041.nasl 8457 2018-01-18 07:58:32Z teissa $
#
# Microsoft .NET Framework XML HMAC Truncation Vulnerability (981343)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Updated By: Madhuri D <dmadhuri@secpod.com> on 2010-11-15
#   - To detect file version 'System.Security.dll' on vista, win 2008 and win 7 os
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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

tag_impact = "Successful exploitation will allow the attackers to forge an XML signature that
  will be accepted as valid or to bypass security restrictions.
  Impact Level: System/Application.";
tag_affected = "Microsoft .NET Framework 3.5/SP 1
  Microsoft .NET Framework 1.1 SP 1
  Microsoft .NET Framework 1.0 SP 3
  Microsoft .NET Framework 2.0 SP 1/SP 2";
tag_insight = "The issue is caused by an error in the XML Signature Syntax and Processing
  (XMLDsig) implementation that rely on the 'HMACOutputLength' parameter to
  determine the number of bytes of the signature to be verified.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://technet.microsoft.com/en-us/security/bulletin/MS10-041";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS10-041.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902193");
  script_version("$Revision: 8457 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-18 08:58:32 +0100 (Thu, 18 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-06-09 17:19:57 +0200 (Wed, 09 Jun 2010)");
  script_cve_id("CVE-2009-0217");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_name("Microsoft .NET Framework XML HMAC Truncation Vulnerability (981343)");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/981343");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/1398");
  script_xref(name : "URL" , value : "http://technet.microsoft.com/en-us/security/bulletin/MS10-041");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
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

if(hotfix_check_sp(xp:4, win2k:5, win2003:3,  winVista:3, win2008:3, win7:1) <= 0){
  exit(0);
}

# MS10-041 Hotfix check
if((hotfix_missing(name:"979907") == 0) || (hotfix_missing(name:"979906") == 0) ||
   (hotfix_missing(name:"979909") == 0) || (hotfix_missing(name:"979904") == 0) ||
   (hotfix_missing(name:"982865") == 0) || (hotfix_missing(name:"979913") == 0) ||
   (hotfix_missing(name:"979911") == 0) || (hotfix_missing(name:"979910") == 0) ||
   (hotfix_missing(name:"979916") == 0 )){
    exit(0);
}

key  = "SOFTWARE\Microsoft\Windows\CurrentVersion\SharedDlls\";
if(registry_key_exists(key:key))
{
  # Get the location of System.Security.dll
  foreach dllPath (registry_enum_values(key:key))
  {
    if((".NET" >< dllPath) && ("System.Security.dll" >< dllPath))
    {
      share = ereg_replace(pattern:"([a-zA-Z]):.*", replace:"\1$", string:dllPath);
      file = ereg_replace(pattern:"[a-zA-Z]:(.*)", replace:"\1", string:dllPath);

      # Get the version of System.Security.dll
      dllVer = GetVer(file:file, share:toupper(share));
      if(!isnull(dllVer))
      {
        # Check forSystem.Security.dll 1  < 1.1.4322.2463, 2.0.50727.4434, 2.0.50727.1879
        if(version_in_range(version:dllVer, test_version:"1.1",test_version2:"1.1.4322.2462") ||
           version_in_range(version:dllVer, test_version:"2.0.50727.1000",test_version2:"2.0.50727.1878")||
           version_in_range(version:dllVer, test_version:"2.0.50727.4000",test_version2:"2.0.50727.4433"))
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
    # Get the version of system.security.dll
    dllVer = fetch_file_version(sysPath:path, file_name:"system.security.dll");
    if(dllVer)
    {
      ## Windows 2008 Server and vista
      if(hotfix_check_sp(winVista:3, win2008:3) > 0)
      {
        # Check for System.Security.dll version < 1.1.4322.2463, 2.0.50727.3613, 2.0.50727.1878, 2.0.50727.4204
        if(version_in_range(version:dllVer, test_version:"1.1",test_version2:"1.1.4322.2462") ||
           version_in_range(version:dllVer, test_version:"2.0.50727.1000", test_version2:"2.0.50727.1877") ||
           version_in_range(version:dllVer, test_version:"2.0.50727.3000", test_version2:"2.0.50727.3612") ||
           version_in_range(version:dllVer, test_version:"2.0.50727.4000", test_version2:"2.0.50727.4203") ||
           version_in_range(version:dllVer, test_version:"2.0.50727.4400", test_version2:"2.0.50727.4433"))
        {
          security_message(0);
          exit(0);
        }
      }

      ## Windows 7
      if(hotfix_check_sp(win7:1) > 0)
      {
        # Check for System.Security.dll version < 2.0.50727.4951
        if(version_in_range(version:dllVer, test_version:"2.0.50727.4000", test_version2:"2.0.50727.4950") ||
           version_in_range(version:dllVer, test_version:"2.0.50727.5000", test_version2:"2.0.50727.5006"))
        {
          security_message(0);
          exit(0);
        }
      }
    }
  }
}
