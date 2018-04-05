###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_office_web_apps_kb3191888.nasl 9313 2018-04-05 06:23:26Z cfischer $
#
# Microsoft Office Web Apps Multiple Remote Code Execution Vulnerabilities (KB3191888)
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

CPE = "cpe:/a:microsoft:office_web_apps";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811026");
  script_version("$Revision: 9313 $");
  script_cve_id("CVE-2017-0254", "CVE-2017-0281");
  script_bugtraq_id(98101, 98297);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-05 08:23:26 +0200 (Thu, 05 Apr 2018) $");
  script_tag(name:"creation_date", value:"2017-05-10 09:10:39 +0530 (Wed, 10 May 2017)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Office Web Apps Multiple Remote Code Execution Vulnerabilities (KB3191888)");

  script_tag(name:"summary", value:"This host is missing an important security
  update for Microsoft Office Web Apps according to Microsoft KB3191888");

  script_tag(name:"vuldetect", value:"Get the vulnerable file version and check
  appropriate patch is applied or not.");

  script_tag(name:"insight", value:"Multiple flaws exists as the software fails to
  properly handle objects in memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  attacker to run arbitrary code in the context of the current user. If the
  current user is logged on with administrative user rights, an attacker could
  take control of the affected system. An attacker could then install programs /
  view, change, or delete data / or create new accounts with full user rights.

  Impact Level: System/Application");

  script_tag(name:"affected", value:"Microsoft Office Web Apps 2013 Service
  Pack 1 and prior.");

  script_tag(name:"solution", value:"Run Windows Update and update the listed
  hotfixes or download and update mentioned hotfixes in the advisory from the
  https://support.microsoft.com/en-us/help/3191888");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name : "URL" , value : "https://support.microsoft.com/en-us/help/3191888");
  script_xref(name : "URL" , value : "https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2017-0254");
  script_xref(name : "URL" , value : "https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2017-0281");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
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

##Microsoft Office Web Apps 2013
if(webappVer =~ "^(15\.)")
{
  dllVer = fetch_file_version(sysPath:path,
           file_name:"\15.0\WebServices\ConversionService\Bin\Converter\sword.dll");

  if(dllVer)
  {
    if(version_in_range(version:dllVer, test_version:"15.0", test_version2:"15.0.4927.0999"))
    {
      report = 'File checked:     ' +  path + "15.0\WebServices\ConversionService\Bin\Converter\sword.dll" + '\n' +
               'File version:     ' +  dllVer  + '\n' +
               'Vulnerable range: ' + "15.0 - 15.0.4927.0999" + '\n' ;
      security_message(data:report);
      exit(0);
    }
  }
}

exit(99);