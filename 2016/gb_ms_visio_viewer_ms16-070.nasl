###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_visio_viewer_ms16-070.nasl 5867 2017-04-05 09:01:13Z teissa $
#
# Microsoft Visio Viewer Remote Code Execution Vulnerability (3163610)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.807843");
  script_version("$Revision: 5867 $");
  script_cve_id("CVE-2016-3235");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-04-05 11:01:13 +0200 (Wed, 05 Apr 2017) $");
  script_tag(name:"creation_date", value:"2016-06-15 12:49:59 +0530 (Wed, 15 Jun 2016)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Visio Viewer Remote Code Execution Vulnerability (3163610)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Bulletin MS16-070");

  script_tag(name:"vuldetect", value:"Get the vulnerable file version and check
  appropriate patch is applied or not.");

  script_tag(name:"insight", value:"The flaw exists due to error within Office
  software when Windows improperly validates input before loading libraries.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to run arbitrary code in the context of the current user and to
  perform actions in the security context of the current user.

  Impact Level: System/Application");

  script_tag(name:"affected", value:"
  Microsoft Visio Viewer 2007 Service Pack 3
  Microsoft Visio Viewer 2010");

  script_tag(name:"solution", value:"Run Windows Update and update the listed
  hotfixes or download and update mentioned hotfixes in the advisory from the
  below link,  https://technet.microsoft.com/library/security/MS16-070");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "https://support.microsoft.com/en-us/kb/2596915");
  script_xref(name : "URL" , value : "https://support.microsoft.com/en-us/kb/2999465");
  script_xref(name : "URL" , value : "https://support.microsoft.com/en-us/kb/3163610");
  script_xref(name : "URL" , value : "https://technet.microsoft.com/library/security/MS16-070");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_mandatory_keys("SMB/Office/VisioViewer/Ver");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");


## Variable Initialization
viewerPath = "";

## Get the KB for visio viewer 
viewerPath = get_kb_item("SMB/Office/VisioViewer/Path");
if(!viewerPath){
  exit(0);
}

vvVer = fetch_file_version(sysPath:viewerPath, file_name:"VVIEWER.DLL");
if(!vvVer){
  exit(0);
}

## Visio Viewer 2007/2010
if(vvVer =~ "^(12|14)\..*")
{
  if(vvVer =~ "^(12)"){
    Vulnerable_range  =  "12 - 12.0.6676.4999";
  }
  else if(vvVer =~ "^(14)"){
    Vulnerable_range  =  "14 - 14.0.7163.4999";
  }
  
  ##Check for vviewer.dll file version
  if(version_in_range(version:vvVer, test_version:"14.0", test_version2:"14.0.7163.4999")||
     version_in_range(version:vvVer, test_version:"12.0", test_version2:"12.0.6676.4999"))
  {
    report = 'File checked:     ' + viewerPath + "\vviewer.dll" + '\n' +
             'File version:     ' + vvVer  + '\n' +
             'Vulnerable range: ' + Vulnerable_range + '\n' ;
    security_message(data:report);
    exit(0);
  }
}
