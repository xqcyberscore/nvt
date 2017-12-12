###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_asp_dotnet_core_dos_vuln.nasl 8063 2017-12-09 11:46:24Z teissa $
#
# Microsoft ASP.NET Core Denial of Service Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.812099");
  script_version("$Revision: 8063 $");
  script_cve_id("CVE-2017-11883");
  script_bugtraq_id(101835);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-12-09 12:46:24 +0100 (Sat, 09 Dec 2017) $");
  script_tag(name:"creation_date", value:"2017-11-20 15:14:33 +0530 (Mon, 20 Nov 2017)");
  script_name("Microsoft ASP.NET Core Denial of Service Vulnerability");

  script_xref(name:"URL", value:"https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2017-11883");
  script_xref(name:"URL", value:"Microsoft ASP.NET Core Denial of Service Vulnerability (CVE-2017-11883)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft advisory (CVE-2017-11883).");

  script_tag(name:"vuldetect", value:"Get the installed version of ASP.NET Core
  and check for affected packages.");

  script_tag(name:"insight", value:"The flaw exists due to an error in ASP.NET
  Core which improperly handles certain crafted web requests.");

  script_tag(name:"impact" , value:"Successful exploitation will allow remote
  attackers to cause a denial-of-service condition.

  Impact Level: Application.");

  script_tag(name:"affected", value:"Microsoft ASP.NET Core 1.0 using packages
  'Microsoft.AspNetCore.Server.WebListener' and 'Microsoft.Net.Http.Server'
  with version 1.0.0, 1.0.1, 1.0.2, 1.0.3, 1.0.4 or 1.0.5. Microsoft ASP.NET Core 1.1
  using packages 'Microsoft.AspNetCore.Server.WebListener' and
  'Microsoft.Net.Http.Server' with version 1.1.0, 1.1.1, 1.1.2 or 1.1.3. Microsoft
  ASP.NET Core 2.0 using packages 'Microsoft.AspNetCore.Server.HttpSys' with version
  2.0.0 and 2.0.1.");

  script_tag(name:"solution", value:"Upgrade Microsoft ASP.NET Core 1.0 to use
  package 'Microsoft.AspNetCore.Server.WebListener' and 'Microsoft.Net.Http.Server' 
  version 1.0.6 or later. Also upgrade Microsoft ASP.NET Core 1.1 to use package
  'Microsoft.AspNetCore.Server.WebListener' and 'Microsoft.Net.Http.Server' version
  1.1.4 or later. Upgrade Microsoft ASP.NET Core 2.0 to use package
  'Microsoft.AspNetCore.Server.HttpSys' version 2.0.2 or later.
  For details refer to https://github.com/aspnet/announcements/issues/278");

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

host    = get_host_ip();
usrname = get_kb_item( "SMB/login" );
passwd  = get_kb_item( "SMB/password" );
if( ! host || ! usrname || ! passwd ) exit( 0 );

domain  = get_kb_item( "SMB/domain" );
if( domain ) usrname = domain + '\\' + usrname;

handle = wmi_connect( host:host, username:usrname, password:passwd );
if( ! handle ) exit( 0 );

query1 = 'Select Version from CIM_DataFile Where FileName ='
        + raw_string(0x22) + 'Microsoft.AspNetCore.Server.WebListener' + raw_string(0x22) + ' AND Extension ='
        + raw_string(0x22) + 'dll' + raw_string(0x22);
fileVer1 = wmi_query( wmi_handle:handle, query:query1);

query2 = 'Select Version from CIM_DataFile Where FileName ='
        + raw_string(0x22) + 'Microsoft.Net.Http.Server' + raw_string(0x22) + ' AND Extension ='
        + raw_string(0x22) + 'dll' + raw_string(0x22);
fileVer2 = wmi_query( wmi_handle:handle, query:query2);

query3 = 'Select Version from CIM_DataFile Where FileName ='
        + raw_string(0x22) + 'Microsoft.AspNetCore.Server.HttpSys' + raw_string(0x22) + ' AND Extension ='
        + raw_string(0x22) + 'dll' + raw_string(0x22);
fileVer3 = wmi_query( wmi_handle:handle, query:query3);

wmi_close( wmi_handle:handle );
if(!fileVer1 && !fileVer2 && !fileVer3) exit( 0 );

foreach ver(split( fileVer1 ))
{
  ver = eregmatch(pattern:"(.*)\microsoft.aspnetcore.server.weblistener.dll.?([0-9.]+)", string:ver );
  version = ver[2];
  file = ver[1] + "Microsoft.AspNetCore.Server.WebListener.dll";
  if(version =~ "^(1\.0)" && version_is_less(version:version, test_version:"1.0.6"))
  {
    fix = "1.0.6";
    break;
  }
  else if(version =~ "^(1\.1)" && version_is_less(version:version, test_version:"1.1.4"))
  {
    fix = "1.1.4";
    break;
  }
}

foreach ver2(split( fileVer2 ))
{
  ver2 = eregmatch(pattern:"(.*)\microsoft.net.http.server.dll.?([0-9.]+)", string:ver2 );
  version2 = ver2[2];
  file2 = ver2[1] + "Microsoft.Net.Http.Server.dll";

  if(version2 =~ "^(1\.0)" && version_is_less(version:version2, test_version:"1.0.6"))
  {
    fix2 = "1.0.6";
    break;
  }

  else if(version2 =~ "^(1\.1)" && version_is_less(version:version2, test_version:"1.1.4"))
  {
    fix2 = "1.1.4";
    break;
  }
}

foreach ver3(split( fileVer3 ))
{
  ver3 = eregmatch(pattern:"(.*)\microsoft.aspnetcore.server.httpsys.dll.?([0-9.]+)", string:ver3);
  version3 = ver3[2];
  file3 = ver3[1] + "Microsoft.AspNetCore.Server.HttpSys.dll";

  if(version3 =~ "^(2\.0)" && version_is_less(version:version3, test_version:"2.0.2"))
  {
    fix3 = "2.0.2";
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
  report2 = report_fixed_ver( installed_version:version2, fixed_version:fix2, file_checked:file2);
  security_message( data:report2);
}

if(fix3)
{
  report3 = report_fixed_ver( installed_version:version3, fixed_version:fix3, file_checked:file3);
  security_message( data:report3);
  exit(0);
}
exit(0);
