###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_office_web_apps_ms16-133.nasl 9316 2018-04-05 07:06:02Z cfischer $
#
# Microsoft Office Web Apps Multiple Vulnerabilities (3199168)
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

CPE = "cpe:/a:microsoft:office_web_apps";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809726");
  script_version("$Revision: 9316 $");
  script_cve_id("CVE-2016-7230", "CVE-2016-7233", "CVE-2016-7234");
  script_bugtraq_id(94006, 94031, 94020);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-05 09:06:02 +0200 (Thu, 05 Apr 2018) $");
  script_tag(name:"creation_date", value:"2016-11-09 16:20:19 +0530 (Wed, 09 Nov 2016)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Office Web Apps Multiple Vulnerabilities (3199168)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Bulletin MS16-133");

  script_tag(name:"vuldetect", value:"Get the vulnerable file version and check
  appropriate patch is applied or not.");

  script_tag(name:"insight", value:"The flaw exists as,

  - Office software fails to properly handle objects in memory.

  - Office or Word reads out of bound memory due to an uninitialized variable.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code in the context of the currently logged-in
  user and gain access to potentially sensitive information.

  Impact Level: System/Application");

  script_tag(name:"affected", value:"Microsoft Office Web Apps 2010 Service Pack 2 and prior.

  Microsoft Office Web Apps Server 2013 Service Pack 1 and prior.");

  script_tag(name:"solution", value:"Run Windows Update and update the listed
  hotfixes or download and update mentioned hotfixes in the advisory from the
  https://technet.microsoft.com/library/security/MS16-133");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "https://support.microsoft.com/en-us/kb/3127954");
  script_xref(name : "URL" , value : "https://support.microsoft.com/en-us/kb/3127929");
  script_xref(name : "URL" , value : "https://technet.microsoft.com/library/security/MS16-133");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_office_web_apps_detect.nasl");
  script_mandatory_keys("MS/Office/Web/Apps/Ver");
  exit(0);
}

include("smb_nt.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) ) exit( 0 );
webappVer = infos['version'];
path = infos['location'];
if(!path || "Could not find the install location" >< path){
  exit(0);
}

## Microsoft Office Web Apps 2010 and 2013
if(webappVer =~ "^(14|15)\..*")
{
  dllVer = fetch_file_version(sysPath:path,
           file_name:"\14.0\WebServices\ConversionService\Bin\Converter\sword.dll");
  if(dllVer)
  {
    if(version_in_range(version:dllVer, test_version:"14.0", test_version2:"14.0.7176.4999"))
    {
     report = 'File checked:     ' +  path + "14.0\WebServices\ConversionService\Bin\Converter\sword.dll" + '\n' +
              'File version:     ' + dllVer  + '\n' +
              'Vulnerable range: ' + "14.0 - 14.0.7176.4999" + '\n' ;
      security_message(data:report);
      exit(0);
    }
  }

  dllVer1 = fetch_file_version(sysPath:path,
           file_name:"\15.0\WebServices\ConversionService\Bin\Converter\sword.dll");
  if(dllVer1)
  {
    if(version_in_range(version:dllVer1, test_version:"15.0", test_version2:"15.0.4875.0999"))
    {
      report = 'File checked:     ' +  path + "15.0\WebServices\ConversionService\Bin\Converter\sword.dll" + '\n' +
               'File version:     ' + dllVer1  + '\n' +
               'Vulnerable range: ' + "15.0 - 15.0.4875.0999" + '\n' ;
      security_message(data:report);
      exit(0);
    }
  }
}

exit(99);