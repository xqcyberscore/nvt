###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms10-072.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Microsoft SharePoint SafeHTML Information Disclosure Vulnerabilities (2412048)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
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

tag_impact = "Successful exploitation could allow remote attackers to gain sensitie
  information via a specially crafted script using SafeHTML.
  Impact Level: Application";
tag_affected = "Microsoft Office SharePoint Server 2007 Service Pack 2
  Microsoft Windows SharePoint Services 3.0 Service Pack 2";
tag_insight = "Multiple flaws are due to the way SafeHTML function sanitizes HTML content.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://technet.microsoft.com/en-us/security/bulletin/MS10-072";
tag_summary = "This host is missing an important security update according to
  Microsoft Bulletin MS10-072.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902626");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-09-22 10:24:03 +0200 (Thu, 22 Sep 2011)");
  script_cve_id("CVE-2010-3243", "CVE-2010-3324");
  script_bugtraq_id(42467, 43703);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Microsoft SharePoint SafeHTML Information Disclosure Vulnerabilities (2412048)");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2412048");
  script_xref(name : "URL" , value : "http://technet.microsoft.com/en-us/security/bulletin/MS10-072");

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

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";

## MS10-072 Hotfix
if(hotfix_missing(name:"2345304") == 1)
{
  ## Microsoft SharePoint Server 2007
  key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";

  if(registry_key_exists(key:key))
  {
    foreach item (registry_enum_keys(key:key))
    {
      appName = registry_get_sz(item:"DisplayName", key:key + item);
      if("Microsoft Office SharePoint Server 2007" >< appName)
      {
        dllPath =  registry_get_sz(item:"BinPath",
                              key:"SOFTWARE\Microsoft\Office Server\12.0");

        if(dllPath)
        {
          dllPath = dllPath + "web server extensions\12\ISAPI";
          vers  = fetch_file_version(sysPath:dllPath,
                                   file_name:"Microsoft.office.server.dll");
          if(vers)
          {
            ## Check for Microsoft.sharepoint.publishing.dl version < 12.0.6539.5000
            if(version_is_less(version:vers, test_version:"12.0.6539.5000"))
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

## Hotfix check
if(hotfix_missing(name:"2345212") == 0){
  exit(0);
}

## Microsoft Windows SharePoint Services
if(!registry_key_exists(key:key)){
  exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  srvcName = registry_get_sz(item:"DisplayName", key:key + item);
  if("Microsoft Windows SharePoint Services" >< srvcName)
  {
    dllPath =  registry_get_sz(item:"SharedFilesDir",
               key:"SOFTWARE\Microsoft\Shared Tools");

    if(!dllPath){
      exit(0);
    }

    dllPath = dllPath + "web server extensions\12\BIN";
    dllVer  = fetch_file_version(sysPath:dllPath, file_name:"Onetutil.dll");

    if(!dllVer){
      exit(0);
    }

    ## Check for onetutil.dll version < 12.0.6545.5002 for Sharepoint services 3.0
    if(version_is_less(version:dllVer, test_version:"12.0.6545.5002"))
    {
      security_message(0);
      exit(0);
    }
  }
}
