###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms12-070.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# Microsoft SQL Server Report Manager Cross Site Scripting Vulnerability (2754849)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
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

tag_impact = "Successful exploitation could allow remote attackers to gain sensitive
  information or execute arbitrary code in the context of the current user.
  Impact Level: Application";
tag_affected = "Microsoft SQL Server 2012
  Microsoft SQL Server 2005 Service Pack 4 and prior
  Microsoft SQL Server 2008 Service Pack 2 and prior
  Microsoft SQL Server 2008 Service Pack 3 and prior
  Microsoft SQL Server 2000 Reporting Services Service Pack 2";
tag_insight = "An error exists in the SQL Server Reporting Services (SSRS),  which can be
  exploited to insert client-side script code.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://technet.microsoft.com/en-us/security/bulletin/ms12-070";
tag_summary = "This host has important security update missing according to
  Microsoft Bulletin MS12-070.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902689");
  script_version("$Revision: 9352 $");
  script_cve_id("CVE-2012-2552");
  script_bugtraq_id(55783);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-10-10 09:46:39 +0530 (Wed, 10 Oct 2012)");
  script_name("Microsoft SQL Server Report Manager Cross Site Scripting Vulnerability (2754849)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/50901");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2754849");
  script_xref(name : "URL" , value : "http://www.securitytracker.com/id/1027623");
  script_xref(name : "URL" , value : "http://technet.microsoft.com/en-us/security/bulletin/ms12-070");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
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

## Variables Initialization
sysPath = "";
dllVer = "";
exeVer = "";
sysPath = "";
sysVer = "";

## Microsoft SQL Server 2000 Reporting Service
key = "SOFTWARE\Microsoft\Microsoft SQL Server\Reporting Services\Version";
if(registry_key_exists(key:key))
{
  exeVer = registry_get_sz(key:key, item:"Version");

  if(exeVer)
  {
    ## Check for  version less than 8.0.1077.0
    if(version_is_less(version:exeVer, test_version:"8.0.1077.0"))
    {
      security_message(0);
      exit(0);
    }
  }
}

## Check if Reporting Service is installed
key = "SOFTWARE\Microsoft\Microsoft SQL Server\Services\Report Server";
if(!registry_key_exists(key:key)){
   exit(0);
}

## Check the server installation
key = "SOFTWARE\Microsoft\Microsoft SQL Server\";
if(registry_key_exists(key:key))
{
  foreach item (registry_enum_keys(key:key))
  {
    ## Get the exe file path from registry
    sysPath = registry_get_sz(key:key + item + "\Tools\Setup", item:"SQLPath");

    if("Microsoft SQL Server" >< sysPath)
    {
      ## Get the version from registry
      sysVer = fetch_file_version(sysPath,
                file_name:"Binn\VSShell\Common7\IDE\Microsoft.reportingservices.diagnostics.dll");

      if(sysVer)
      {
        ## SQL Server 2005 Service Pack 4 GDR/QFE,
        ## SQL Server 2008 Service Pack 2 GDR/QFE,  SQL Server 2008 Service Pack 3 GDR/QFE
        ##  SQL Server 2008 R2 SP1 QFE/GDR
        ## SQL Server 2012
        if(version_in_range(version:sysVer, test_version:"9.0.5000", test_version2:"9.0.5068")||
           version_in_range(version:sysVer, test_version:"9.0.5200", test_version2:"9.0.5323"))
## TODO
## Not Tested on SQL 2008 and 2012 ( Due to installer issue)
## MSSQL 2008 R2 (evaluation edition could not apply patch)
## Once fixed uncomment the below code
#           version_in_range(version:sysVer, test_version:"10.00.4000", test_version2:"10.00.4066")||
#           version_in_range(version:sysVer, test_version:"10.00.4260", test_version2:"10.00.4370")||
#           version_in_range(version:sysVer, test_version:"10.00.5500", test_version2:"10.00.5511")||
#           version_in_range(version:sysVer, test_version:"10.00.5750", test_version2:"10.00.5825")||
#           version_in_range(version:sysVer, test_version:"10.50.2500", test_version2:"10.50.2549")||
#           version_in_range(version:sysVer, test_version:"10.50.2750", test_version2:"10.50.2860")||
#           version_in_range(version:sysVer, test_version:"11.0.2100", test_version2:"11.0.2217")||
#           version_in_range(version:sysVer, test_version:"11.0.2300", test_version2:"11.0.2375"))
        {
          security_message(0);
          exit(0);
        }
      }
    }
  }
}
