###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_webdav_rce_vuln_kb3197835.nasl 7571 2017-10-26 07:59:06Z cfischer $
#
# Microsoft Windows 'WebDAV' Remote Code Execution Vulnerability (KB3197835)
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
  script_oid("1.3.6.1.4.1.25623.1.0.811206");
  script_version("$Revision: 7571 $");
  script_cve_id("CVE-2017-7269");
  script_bugtraq_id(97127);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-10-26 09:59:06 +0200 (Thu, 26 Oct 2017) $");
  script_tag(name:"creation_date", value:"2017-06-16 12:56:08 +0530 (Fri, 16 Jun 2017)");
  script_name("Microsoft Windows 'WebDAV' Remote Code Execution Vulnerability (KB3197835)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl", "gb_wmi_access.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("WMI/access_successful", "SMB/WindowsVersion");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/3197835");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB3197835");

  script_tag(name:"vuldetect", value:"Get the vulnerable file version and
  check appropriate patch is applied or not.");

  script_tag(name:"insight", value:"The flaw exists due to an error in IIS when
  WebDAV improperly handles objects in memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to execute arbitrary code in the context of current user.

  Impact Level: System");

  script_tag(name:"affected", value:"Microsoft Windows XP SP2 x64

  Microsoft Windows XP SP3 x86

  Microsoft Windows 2003 x32/x64 Edition Service Pack 2 and prior.");

  script_tag(name:"solution", value:"Run Windows Update and update the
  listed hotfixes or download and update mentioned hotfixes in the advisory
  from the below link,
  https://support.microsoft.com/en-us/help/3197835");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("secpod_reg.inc");
include("version_func.inc");

## Check for OS and Service Pack
if( hotfix_check_sp( xp:4, xpx64:3, win2003:3, win2003x64:3 ) <= 0 ) exit( 0 );

host    = get_host_ip();
usrname = get_kb_item( "SMB/login" );
passwd  = get_kb_item( "SMB/password" );
if( ! host || ! usrname || ! passwd ) exit( 0 );
domain  = get_kb_item( "SMB/domain" );
if( domain ) usrname = domain + '\\' + usrname;

handle = wmi_connect( host:host, username:usrname, password:passwd );
if( ! handle ) exit( 0 );

## WMI query to grep the file version of 'httpext.dll'
query = 'Select Version from CIM_DataFile Where FileName ='
        + raw_string(0x22) + 'httpext' + raw_string(0x22) + ' AND Extension ='
        + raw_string(0x22) + 'dll' + raw_string(0x22);
fileVer = wmi_query( wmi_handle:handle, query:query );
wmi_close( wmi_handle:handle );
if( ! fileVer ) exit( 0 );

# Don't pass NULL to version function below
maxVer = "";

##Multiple files found
##On update old as well as new files come, so checking for highest version
foreach ver( split( fileVer ) ) {
  ## Math version
  ver1 = eregmatch( pattern:"(.*)\httpext.dll.?([0-9.]+)", string:ver );
  if( ! ver1 ) exit( 0 );

  version = ver1[2];
  winPath = ver1[1];

  if( version_is_less( version:version, test_version:maxVer ) ) {
    continue;
  } else {
    maxVer = version;
  }
}

if( maxVer ) {
  ## Windows XP
  if( hotfix_check_sp( xp:4 ) > 0 ) {
    ## Check for httpext.dll version
    if( version_is_less( version:maxVer, test_version:"6.0.2600.7150" ) ) {
      Vulnerable_range = "Less than 6.0.2600.7150";
      VULN = TRUE;
    }
  }

  ## Windows 2003, Windows XP SP2 64bit
  else if( hotfix_check_sp( win2003:3, win2003x64:3, xpx64:3 ) > 0 ) {
    ## Check for httpext.dll version
    if( version_is_less( version:maxVer, test_version:"6.0.3790.5955" ) ) {
      Vulnerable_range = "Less than 6.0.3790.5955";
      VULN = TRUE;
    }
  }
}

if( VULN ) {
  report = 'File checked:     ' + winPath + "httpext.dll" + '\n' +
           'File version:     ' + maxVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range + '\n' ;
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
