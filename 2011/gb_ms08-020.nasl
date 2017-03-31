###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms08-020.nasl 5362 2017-02-20 12:46:39Z cfi $
#
# Microsoft Windows DNS Client Service Response Spoofing Vulnerability (945553)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright: 
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation could allow remote attackers to spoof DNS replies,
  allowing them to redirect network traffic and to launch man-in-the-middle attacks.
  Impact Level: System";
tag_affected = "Microsoft Windows 2K/XP/2003/Vista";
tag_insight = "The flaws are due to the Windows DNS client using predictable
  transaction IDs in outgoing queries and can be exploited to poison the DNS
  cache when the transaction ID is guessed.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link.
  http://www.microsoft.com/technet/security/bulletin/ms08-020.mspx";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS08-020.";

if(description)
{
  script_id(801701);
  script_version("$Revision: 5362 $");
  script_tag(name:"last_modification", value:"$Date: 2017-02-20 13:46:39 +0100 (Mon, 20 Feb 2017) $");
  script_tag(name:"creation_date", value:"2011-01-10 14:22:58 +0100 (Mon, 10 Jan 2011)");
  script_tag(name:"cvss_base", value:"8.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:C/A:C");
  script_cve_id("CVE-2008-0087");
  script_bugtraq_id(28553);
  script_name("Microsoft Windows DNS Client Service Response Spoofing Vulnerability (945553)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/29696");
  script_xref(name : "URL" , value : "http://securitytracker.com/alerts/2008/Apr/1019802.html");
  script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/bulletin/ms08-020.mspx");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

## This function will return the version of the given file
function get_file_version(sysPath, file_name)
{
  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:sysPath);
  file =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",
                       string:sysPath + "\" + file_name);

  sysVer = GetVer(file:file, share:share);
  if(!sysVer){
    return(FALSE);
  }

  return(sysVer);
}

if(hotfix_check_sp(xp:4, win2k:5, win2003:3, winVista:2) <= 0){
  exit(0);
}

# Check for Hotfix 945553 (MS08-020).
if(hotfix_missing(name:"945553") == 0){
  exit(0);
}

## Get System32 path
sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\COM3\Setup",
                          item:"Install Path");
if(sysPath)
{
  dllVer = get_file_version(sysPath, file_name:"dnsapi.dll");
  if(dllVer)
  {
    if(hotfix_check_sp(win2k:5) > 0)
    {
      # Check for dnsapi.dll version < 5.0.2195.7151
      if(version_is_less(version:dllVer, test_version:"5.0.2195.7151")){
        security_message(0);
      }
    }

    else if(hotfix_check_sp(xp:4) > 0)
    {
      SP = get_kb_item("SMB/WinXP/ServicePack");
      if("Service Pack 2" >< SP)
      {
        # Check for dnsapi.dll version < 5.1.2600.3316
        if(version_is_less(version:dllVer, test_version:"5.1.2600.3316")){
          security_message(0);
        }
      }
    }
    
    else if(hotfix_check_sp(win2003:3) > 0)
    {
      SP = get_kb_item("SMB/Win2003/ServicePack");
      if("Service Pack 1" >< SP)
      {
        # Check for dnsapi.dll version < 5.2.3790.3092
        if(version_is_less(version:dllVer, test_version:"5.2.3790.3092")){
          security_message(0);
        }
      }
      else if("Service Pack 2" >< SP)
      {
        # Check for dnsapi.dll version < 5.2.3790.4238
        if(version_is_less(version:dllVer, test_version:"5.2.3790.4238")){
          security_message(0);
        }
      }
      else security_message(0);
    }
  }
}

## Get System32 path
sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
                          item:"PathName");
if(sysPath)
{
  dllVer = get_file_version(sysPath, file_name:"System32\dnsapi.dll");
  if(dllVer)
  {
    # Windows Vista
    if(hotfix_check_sp(winVista:2) > 0)
    {
      # Grep for dnsapi.dll version < 6.0.6000.16615
      if(version_is_less(version:dllVer, test_version:"6.0.6000.16615")){
          security_message(0);
        }
         exit(0);
    }
  }
}

