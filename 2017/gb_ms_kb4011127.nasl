###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_kb4011127.nasl 9313 2018-04-05 06:23:26Z cfischer $
#
# Microsoft SharePoint Enterprise Server 2016 Multiple Vulnerabilities (KB4011127)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.811742");
  script_version("$Revision: 9313 $");
  script_cve_id("CVE-2017-8742", "CVE-2017-8743");
  script_bugtraq_id(100741, 100746);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-05 08:23:26 +0200 (Thu, 05 Apr 2018) $");
  script_tag(name:"creation_date", value:"2017-09-13 08:55:50 +0530 (Wed, 13 Sep 2017)");
  script_name("Microsoft SharePoint Enterprise Server 2016 Multiple Vulnerabilities (KB4011127)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB4011127");

  script_tag(name:"vuldetect", value:"Get the vulnerable file version and
  check appropriate patch is applied or not.");

  script_tag(name:"insight", value:"Multiple flaw exists due to error in Microsoft
  Office software when the software fails to properly handle objects in memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  who successfully exploited the vulnerability to run arbitrary code in the
  context of the current user. 

  Impact Level: System/Application");

  script_tag(name:"affected", value:"Microsoft SharePoint Enterprise Server 2016");

  script_tag(name:"solution", value:"Run Windows Update and update the
  listed hotfixes or download and update mentioned hotfixes in the advisory
  from the below link,
  https://support.microsoft.com/en-us/help/4011127");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name : "URL" , value : "https://support.microsoft.com/en-us/help/4011127");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_sharepoint_sever_n_foundation_detect.nasl");
  script_mandatory_keys("MS/SharePoint/Server/Ver");
  script_require_ports(139, 445);
  exit(0);
}

include("smb_nt.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if( ! infos = get_app_version_and_location( cpe:'cpe:/a:microsoft:sharepoint_server', exit_no_version:TRUE ) ) exit( 0 );
shareVer = infos['version'];
path = infos['location'];
if(!path || "Could not find the install location" >< path){
  exit(0);
}

## Check for SharePoint Server 2016
if(shareVer =~ "^16\..*")
{
  ## Get Common Files Directory
  path = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
                         item:"CommonFilesDir");
  if(path)
  {
    path = path + "\microsoft shared\Web Server Extensions\16\BIN";

    ## Get version from 'Onetutil.dll' file
    dllVer = fetch_file_version(sysPath:path, file_name:"Onetutil.dll");

    if(dllVer && version_in_range(version:dllVer, test_version:"16.0", test_version2:"16.0.4588.0999"))
    {
      report = 'File checked:     ' +  path + "\Onetutil.dll"+ '\n' +
               'File version:     ' +  dllVer  + '\n' +
               'Vulnerable range: 16.0 - 16.0.4588.0999' + '\n' ;
      security_message(data:report);
      exit(0);
    }
  }
}

exit(99);
