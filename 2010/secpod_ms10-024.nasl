###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms10-024.nasl 8244 2017-12-25 07:29:28Z teissa $
#
# Microsoft Exchange and Windows SMTP Service Denial of Service Vulnerability (981832)
#
# Authors:
# Veerendra G <veerendragg@secpod.com>
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

tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://www.microsoft.com/technet/security/Bulletin/MS10-024.mspx";

tag_impact = "Successful exploitation could lead to Denial of Service
  Impact Level: Application";
tag_affected = "Microsoft Windows 2K  Service Pack 4 and prior.
  Microsoft Windows XP  Service Pack 3 and prior.
  Microsoft Windows 2K3 Service Pack 2 and prior.
  Microsoft Exchange Server 2000 Service Pack 3
  Microsoft Exchange Server 2003 Service Pack 2";
tag_insight = "An error exists MS Windows Simple Mail Transfer Protocol (SMTP) component,
  - while handling specially crafted DNS Mail Exchanger (MX) resource records.
  - due to the manner in which the SMTP component handles memory allocation";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS10-024.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900240");
  script_version("$Revision: 8244 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-25 08:29:28 +0100 (Mon, 25 Dec 2017) $");
  script_tag(name:"creation_date", value:"2010-04-23 17:57:39 +0200 (Fri, 23 Apr 2010)");
  script_bugtraq_id(39308, 39381);
  script_cve_id("CVE-2010-0024", "CVE-2010-0025");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Microsoft Exchange and Windows SMTP Service Denial of Service Vulnerability (981832)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/39253");
  script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/Bulletin/MS10-024.mspx");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(xp:4, win2k:5, win2003:3) <= 0){
  exit(0);
}

## Get SMTP Service path
smtpPath = registry_get_sz(key:"SOFTWARE\Microsoft\InetStp",
                          item:"InstallPath");
## SMTP Patch Check
if(smtpPath)
{
  ## Hotfix is missing in registry (1 means missing)
  if(hotfix_missing(name:"976323") == 1)
  {
    share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:smtpPath);
    file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",
                      string:smtpPath + "\smtpsvc.dll");
    exeVer = GetVer(file:file, share:share);

    if(exeVer)
    {
      ## Windows 2K
      if(hotfix_check_sp(win2k:5) > 0)
      {
        ## Grep for Smtpsvc.dll version < 5.0.2195.7381
        if(version_is_less(version:exeVer, test_version:"5.0.2195.7381")){
          security_message(0);
          exit(0);
        }
      }

      ## Windows XP
      else if(hotfix_check_sp(xp:4) > 0)
      {
        SP = get_kb_item("SMB/WinXP/ServicePack");
        if("Service Pack 2" >< SP)
        {
          ## Grep for Smtpsvc.dll version < 6.0.2600.3680
          if(version_is_less(version:exeVer, test_version:"6.0.2600.3680")){
            security_message(0);
            exit(0);
          }
        }
        else if("Service Pack 3" >< SP)
        {
          ## Grep for Smtpsvc.dll version < 6.0.2600.5949
          if(version_is_less(version:exeVer, test_version:"6.0.2600.5949")){
            security_message(0);
            exit(0);
          }
        }
      }

      ## Windows 2003
      else if(hotfix_check_sp(win2003:3) > 0)
      {
        SP = get_kb_item("SMB/Win2003/ServicePack");
        if("Service Pack 2" >< SP)
        {
          ## Grep for Smtpsvc.dll version < 6.0.3790.4675
          if(version_is_less(version:exeVer, test_version:"6.0.3790.4675")){
            security_message(0);
            exit(0);
          }
        }
      }
    }
  }
}

## Get Exchange Installed path
exchangePath = registry_get_sz(key:"SOFTWARE\Microsoft\Exchange\Setup",
                          item:"Services");
## Microsoft Exchange Patch Check
if(exchangePath)
{
  ## MS10-024 Hotfix check in registry
  if(hotfix_missing(name:"976703") == 0 || hotfix_missing(name:"976702") == 0){
    exit(0);
  }

  ## Check for common file for Exchange 2000 and 2003
  common_exspmsg_file = TRUE;
  exePath = registry_get_sz(key:"SOFTWARE\Microsoft\COM3\Setup",
                          item:"Install Path");
  if(!exePath){
    exit(0);
  }

  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:exePath);
  file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",
                      string:exePath + "\exspmsg.dll");
  fileVersion = GetVer(file:file, share:share);

  if(!fileVersion)
  {
    common_exspmsg_file = FALSE;
    share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:exchangePath);
    file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",
                        string:exchangePath + "\bin\Msgfilter.dll");
    fileVersion = GetVer(file:file, share:share);
  }

  if(!fileVersion){
    exit(0);
  }

  ## If common exspmsg.dll file is present
  if(common_exspmsg_file)
  {
    ## Grep for Exspmsg.dll from 6.5 to 6.5.7233.41
    if(version_in_range(version:fileVersion, test_version:"6.5",
                        test_version2:"6.5.7233.40")){
      security_message(0);
    }
  }
  else
  {
    ## Grep for Msgfilter.dll from 6.5 to 6.5.7656.2
    if(version_in_range(version:fileVersion, test_version:"6.5",
                        test_version2:"6.5.7656.1")){
      security_message(0);
    }
  }
}
