###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_powershell_editor_services_rce_vuln.nasl 10538 2018-07-18 10:58:40Z santu $
#
# Microsoft PowerShell Editor Services Remote Code Execution Vulnerability
#
# Authors:
# Rinu Kuriaksoe <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.813676");
  script_version("$Revision: 10538 $");
  script_cve_id("CVE-2018-8327");
  script_bugtraq_id(104649);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-07-18 12:58:40 +0200 (Wed, 18 Jul 2018) $");
  script_tag(name:"creation_date", value:"2018-07-17 14:49:04 +0530 (Tue, 17 Jul 2018)");
  script_name("Microsoft PowerShell Editor Services Remote Code Execution Vulnerability");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft advisory (CVE-2018-8327).");

  script_tag(name:"vuldetect", value:"Get the installed version of 'PowerShell
  Editor Services' and check the version is vulnerable or not.");

  script_tag(name:"insight", value:"The flaw is due to an improper way of securing
  local connections by PowerShell Editor Services.");

  script_tag(name:"impact" , value:"Successful exploitation will allow attackers 
  to execute malicious code on a vulnerable system.

  Impact Level: System/Application");

  script_tag(name:"affected", value:"PowerShell Editor Services 1.7.0 and below.");

  script_tag(name:"solution", value:"Upgrade PowerShell Editor Services to 
  version 1.8.0 or later. For updates refer to Reference links.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2018-8327");
  script_xref(name:"URL", value:"https://github.com/PowerShell/PowerShellEditorServices/issues/703");
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
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

query = 'Select Version from CIM_DataFile Where FileName ='
        + raw_string(0x22) + 'Microsoft.PowerShell.EditorServices' + raw_string(0x22) + ' AND Extension ='
        + raw_string(0x22) + 'dll' + raw_string(0x22);
fileVer = wmi_query( wmi_handle:handle, query:query);

wmi_close( wmi_handle:handle );

if(!fileVer) exit( 0 );

foreach ver(split( fileVer ))
{
  ver = eregmatch(pattern:"(.*)\microsoft.powershell.editorservices.dll.?([0-9.]+)", string:ver );
  version = ver[2];
  file = ver[1] + "Microsoft.PowerShell.EditorServices.dll";

  if(version_is_less(version:version, test_version:"1.8.0"))
  {
    report = report_fixed_ver( installed_version:version, fixed_version:"1.8.0", file_checked:file);
    security_message( data:report );
    exit(0);
  }
}
exit(0);
