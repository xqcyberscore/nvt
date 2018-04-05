###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_kb4011271.nasl 9313 2018-04-05 06:23:26Z cfischer $
#
# Microsoft Office Web Apps 2010 Service Pack 2 Defense in Depth Update (KB4011271)
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.812128");
  script_version("$Revision: 9313 $");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-05 08:23:26 +0200 (Thu, 05 Apr 2018) $");
  script_tag(name:"creation_date", value:"2017-11-15 00:50:03 +0530 (Wed, 15 Nov 2017)");
  script_name("Microsoft Office Web Apps 2010 Service Pack 2 Defense in Depth Update (KB4011271)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB4011271");

  script_tag(name:"vuldetect", value:"Get the vulnerable file version and
  check appropriate patch is applied or not.");

  script_tag(name:"insight", value:"Microsoft has released an update for Microsoft
  Office that provides enhanced security as a defense-in-depth measure.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to compromise system's availability, integrity, and confidentiality.
  
  Impact Level: System/Application");

  script_tag(name:"affected", value:"Microsoft Office Web Apps 2010 Service Pack 2");

  script_tag(name:"solution", value:"Run Windows Update and update the
  listed hotfixes or download and update mentioned hotfixes in the advisory
  from the link, https://support.microsoft.com/en-us/help/4011271");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name : "URL" , value : "https://support.microsoft.com/en-us/help/4011271");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_office_web_apps_detect.nasl");
  script_mandatory_keys("MS/Office/Web/Apps/Ver");
  script_require_ports(139, 445);
  exit(0);
}

include("smb_nt.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if( ! infos = get_app_version_and_location( cpe:'cpe:/a:microsoft:office_web_apps', exit_no_version:TRUE ) ) exit( 0 );
webappVer = infos['version'];
path = infos['location'];
if(!path || "Could not find the install location" >< path){
  exit(0);
}

if(webappVer =~ "^(14\.)")
{
  dllVer = fetch_file_version(sysPath:path,
           file_name:"\14.0\WebServices\ConversionService\Bin\Converter\sword.dll");
  if(dllVer)
  {
    if(version_in_range(version:dllVer, test_version:"14.0", test_version2:"14.0.7190.4999"))
    {
      report = report_fixed_ver(file_checked:path + "\14.0\WebServices\ConversionService\Bin\Converter\sword.dll",
                                file_version:dllVer, vulnerable_range:"14.0 - 14.0.7190.4999");
      security_message(data:report);
      exit(0);
    }
  }
}

exit(99);
