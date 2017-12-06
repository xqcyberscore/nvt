###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_asp_dotnet_core_info_disc_vuln.nasl 7992 2017-12-05 08:34:22Z teissa $
#
# Microsoft ASP.NET Core Information Disclosure Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.812097");
  script_version("$Revision: 7992 $");
  script_cve_id("CVE-2017-8700");
  script_bugtraq_id(101712);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-12-05 09:34:22 +0100 (Tue, 05 Dec 2017) $");
  script_tag(name:"creation_date", value:"2017-11-17 12:17:13 +0530 (Fri, 17 Nov 2017)");
  script_name("Microsoft ASP.NET Core Information Disclosure Vulnerability");

  script_xref(name:"URL", value:"https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2017-8700");
  script_xref(name:"URL", value:"https://github.com/aspnet/announcements/issues/279");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft advisory (CVE-2017-8700).");

  script_tag(name:"vuldetect", value:"Get the installed version of ASP.NET Core
  and check for affected packages.");

  script_tag(name:"insight", value:"The flaw exists due to an unspecified error
  where Cross-Origin Resource Sharing (CORS) can be bypassed.");

  script_tag(name:"impact" , value:"Successful exploitation will allow remote
  attackers to gain access to potentially sensitive information.

  Impact Level: System/Application.");

  script_tag(name:"affected", value:"Microsoft ASP.NET Core 1.0 and ASP.NET Core 1.1
  using 'Microsoft.AspNetCore.Mvc.Core' package or 'Microsoft.AspNetCore.Mvc.Cors'
  package versions 1.0.0, 1.0.1, 1.0.2, 1.0.3, 1.0.4, 1.0.5, 1.1.0, 1.1.1, 1.1.2,
  1.1.3 and 1.1.4");

  script_tag(name:"solution", value:"Upgrade to Microsoft ASP.NET Core 2.0 or higher.
  For Microsoft ASP.NET Core 1.x upgrade 'Microsoft.AspNetCore.Mvc.Core' and
  'Microsoft.AspNetCore.Mvc.Cors' packages to version 1.0.6 or 1.1.5 or later.
  For details refer to https://github.com/aspnet/announcements/issues/279");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Windows");
  script_dependencies("smb_reg_service_pack.nasl", "gb_wmi_access.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("WMI/access_successful", "SMB/WindowsVersion");
  exit(0);
}

include("smb_nt.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");


##Check for packages in projects
host    = get_host_ip();
usrname = get_kb_item( "SMB/login" );
passwd  = get_kb_item( "SMB/password" );

if( ! host || ! usrname || ! passwd ) exit( 0 );

domain  = get_kb_item( "SMB/domain" );

if( domain ) usrname = domain + '\\' + usrname;

handle = wmi_connect( host:host, username:usrname, password:passwd );
if( ! handle ) exit( 0 );

query1 = 'Select Version from CIM_DataFile Where FileName ='
         + raw_string(0x22) + 'Microsoft.AspNetCore.Mvc.Core' + raw_string(0x22) + ' AND Extension ='
         + raw_string(0x22) + 'dll' + raw_string(0x22);
fileVer1 = wmi_query( wmi_handle:handle, query:query1);

query2 = 'Select Version from CIM_DataFile Where FileName ='
         + raw_string(0x22) + 'Microsoft.AspNetCore.Mvc.Cors' + raw_string(0x22) + ' AND Extension ='
         + raw_string(0x22) + 'dll' + raw_string(0x22);
fileVer2 = wmi_query( wmi_handle:handle, query:query2 );

wmi_close( wmi_handle:handle );

if(!fileVer1 && !fileVer2) exit( 0 );
foreach ver(split( fileVer1 ))
{
  ver = eregmatch(pattern:"(.*)\microsoft.aspnetcore.mvc.core.dll.?([0-9.]+)", string:ver );
  version = ver[2];
  file = ver[1] + "Microsoft.AspNetCore.Mvc.Core.dll";

  if(version =~ "^(1\.0)" && version_is_less(version:version, test_version:"1.0.6"))
  {
    fix = "1.0.6";
    break;
  }

  else if(version =~ "^(1\.1)" && version_is_less(version:version, test_version:"1.1.5"))
  {
    fix = "1.1.5";
    break;
  }
}

foreach ver2(split( fileVer2 ))
{
  ver2 = eregmatch(pattern:"(.*)\microsoft.aspnetcore.mvc.cors.dll.?([0-9.]+)", string:ver2 );
  version2 = ver2[2];
  file2 = ver2[1] + "Microsoft.AspNetCore.Mvc.Cors.dll";

  if(version2 =~ "^(1\.0)" && version_is_less(version:version2, test_version:"1.0.6"))
  {   
    fix2 = "1.0.6";
    break;
  }

  if(version2 =~ "^(1\.1)" && version_is_less(version:version2, test_version:"1.1.5"))
  {
    fix2 = "1.1.5";
    break;
  }
}

if(fix)
{
  report = report_fixed_ver( installed_version:version, fixed_version:fix, file_checked:file);
  security_message( data:report );
}

if(fix2)
{
  report1 = report_fixed_ver( installed_version:version2, fixed_version:fix2, file_checked:file2);
  security_message( data:report1);
  exit(0);
}
exit(0);
