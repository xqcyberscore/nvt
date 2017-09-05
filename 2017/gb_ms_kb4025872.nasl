###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_kb4025872.nasl 7051 2017-09-04 11:38:56Z cfischer $
#
# Windows PowerShell Remote Code Execution Vulnerability (KB4025872)
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
  script_oid("1.3.6.1.4.1.25623.1.0.811457");
  script_version("$Revision: 7051 $");
  script_cve_id("CVE-2017-8565");
  script_bugtraq_id(99394);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-09-04 13:38:56 +0200 (Mon, 04 Sep 2017) $");
  script_tag(name:"creation_date", value:"2017-07-12 08:29:18 +0530 (Wed, 12 Jul 2017)");
  script_name("Windows PowerShell Remote Code Execution Vulnerability (KB4025872)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl", "gb_wmi_access.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("WMI/access_successful", "SMB/WindowsVersion");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4025872");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB4025872");

  script_tag(name:"vuldetect", value:"Get the vulnerable file version and
  check appropriate patch is applied or not.");

  script_tag(name:"insight", value:"The flaw exists due to an error in
  PowerShell when PSObject wraps a CIM Instance.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to execute malicious code on a vulnerable system.

  Impact Level: System");

  script_tag(name:"affected", value:"Microsoft Windows Server 2008 x32/x64 Edition Service Pack 2");

  script_tag(name:"solution", value:"Run Windows Update and update the
  listed hotfixes or download and update mentioned hotfixes in the advisory
  from the below link,
  https://support.microsoft.com/en-us/help/4025872");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("secpod_reg.inc");
include("version_func.inc");

## Check for OS and Service Pack
if( hotfix_check_sp( win2008:3, win2008x64:3 ) <= 0 ) exit( 0 );

host    = get_host_ip();
usrname = get_kb_item( "SMB/login" );
passwd  = get_kb_item( "SMB/password" );
if( ! host || ! usrname || ! passwd ) exit( 0 );
domain  = get_kb_item( "SMB/domain" );
if( domain ) usrname = domain + '\\' + usrname;

handle = wmi_connect( host:host, username:usrname, password:passwd );
if( ! handle ) exit( 0 );

## WMI query to grep the file version of 'system.management.automation.dll'
query = 'Select Version from CIM_DataFile Where FileName ='
        + raw_string(0x22) + 'System.Management.Automation' + raw_string(0x22) + ' AND Extension ='
        + raw_string(0x22) + 'dll' + raw_string(0x22);
fileVer = wmi_query( wmi_handle:handle, query:query );
wmi_close( wmi_handle:handle );
if( ! fileVer ) exit( 0 );

foreach ver( split( fileVer ) ) {
  ver1 = eregmatch( pattern:".*system.management.automation.dll|([0-9.]+)", string:ver );
  if( ver1[1] ){
    dllVer = ver1[1];
    break;
  }
}

if( dllVer ) {
  ## Check for system.management.automation.dll version
  if( version_is_less( version:dllVer, test_version:"6.2.9200.22198" ) ) {
    report = 'File checked:  system.management.automation.dll' + '\n' +
             'File version:   ' + dllVer  + '\n' +
             'Vulnerable range: Less than 6.2.9200.22198' ;
    security_message( port:0, data:report );
    exit( 0 );
  }
}

exit( 99 );
