###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms12-061.nasl 6532 2017-07-05 07:42:05Z cfischer $
#
# MS Visual Studio Team Foundation Server Privilege Elevation Vulnerability (2719584)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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

tag_impact = "Successful exploitation could allow an attacker to execute arbitrary HTML and
  script code in a user's browser session in context of an affected site.
  Impact Level: Application";
tag_affected = "Microsoft Visual Studio Team Foundation Server 2010 Service Pack 1";
tag_insight = "The application does not validate certain unspecified input before returning
  it to the user. This may allow a user to create a specially crafted request
  that would execute arbitrary script code in a user's browser.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://technet.microsoft.com/en-us/security/bulletin/ms12-061";
tag_summary = "This host is missing an important security update according to
  Microsoft Bulletin MS12-061.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.903040";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 6532 $");
  script_bugtraq_id(55409);
  script_cve_id("CVE-2012-1892");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-07-05 09:42:05 +0200 (Wed, 05 Jul 2017) $");
  script_tag(name:"creation_date", value:"2012-09-12 11:38:17 +0530 (Wed, 12 Sep 2012)");
  script_name("MS Visual Studio Team Foundation Server Privilege Elevation Vulnerability (2719584)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/50463/");
  script_xref(name : "URL" , value : "http://technet.microsoft.com/en-us/security/bulletin/ms12-061");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_vs_team_foundation_server_detect.nasl");
  script_mandatory_keys("MS/VS/Team/Foundation/Server/Ver");
  script_require_ports(139, 445);

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
include("version_func.inc");
include("secpod_smb_func.inc");

## Confirm Windows
if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

## Variables Initialization
path = "";
version = "";
dllVer = "";

## Get System Path
sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

## Microsoft Visual Studio Team Foundation Server 2010
version = get_kb_item("MS/VS/Team/Foundation/Server/Ver");
if(version && (version =~ "^10\..*"))
{
  path = sysPath + "\assembly\GAC_MSIL\Microsoft.TeamFoundation.WebAccess\10.0.0.0__b03f5f7f11d50a3a";
  if(path)
  {
    ## Get Microsoft.TeamFoundation.WebAccess.dll file version
    dllVer = fetch_file_version(sysPath:path, file_name:"Microsoft.TeamFoundation.WebAccess.dll");
    if(dllVer)
    {
      ## Check for Microsoft.TeamFoundation.WebAccess.dll version
      if(version_is_less(version:dllVer, test_version:"10.0.40219.417")){
        security_message(0);
      }
    }
  }
}
