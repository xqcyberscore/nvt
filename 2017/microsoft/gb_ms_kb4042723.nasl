###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_kb4042723.nasl 7862 2017-11-22 10:11:26Z cfischer $
#
# Windows Server 2008 Defense in Depth (KB4042723)
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
  script_oid("1.3.6.1.4.1.25623.1.0.811950");
  script_version("$Revision: 7862 $");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-11-22 11:11:26 +0100 (Wed, 22 Nov 2017) $");
  script_tag(name:"creation_date", value:"2017-11-10 18:23:04 +0530 (Fri, 10 Nov 2017)");
  script_name("Windows Server 2008 Defense in Depth (KB4042723)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB4042723");

  script_tag(name:"vuldetect", value:"Get the vulnerable file version and
  check appropriate patch is applied or not.");

  script_tag(name:"insight", value:"Microsoft has released an update for
  Microsoft Windows Server 2008 that provides enhanced security as a
  defense-in-depth measure.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to compromise integrity, availability, and confidentiality of the
  system.  

  Impact Level: System");

  script_tag(name:"affected", value:"Microsoft Windows Server 2008 x32/x64 Edition Service Pack 2");

  script_tag(name:"solution", value:"Run Windows Update and update the
  listed hotfixes or download and update mentioned hotfixes in the advisory
  from the link, https://support.microsoft.com/en-us/help/4042723");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name : "URL" , value : "https://support.microsoft.com/en-us/help/4042723");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl", "gb_wmi_access.nasl");
  script_mandatory_keys("WMI/access_successful", "SMB/WindowsVersion");
  script_require_ports(139, 445);
  exit(0);
}


include("secpod_reg.inc");
include("version_func.inc");

if(hotfix_check_sp(win2008:3, win2008x64:3) <= 0){
  exit(0);
}

host    = get_host_ip();
usrname = get_kb_item( "SMB/login" );
passwd  = get_kb_item( "SMB/password" );

if( !host || !usrname || !passwd ) exit( 0 );

domain  = get_kb_item( "SMB/domain" );
if( domain ) usrname = domain + '\\' + usrname;

handle = wmi_connect( host:host, username:usrname, password:passwd );
if( ! handle ) exit( 0 );

query = 'Select Version from CIM_DataFile Where FileName ='
        + raw_string(0x22) + 'nwifi' + raw_string(0x22) + ' AND Extension ='
        + raw_string(0x22) + 'sys' + raw_string(0x22);
fileVer = wmi_query( wmi_handle:handle, query:query );

wmi_close( wmi_handle:handle );
if( ! fileVer ) exit( 0 );
maxVer = NULL;

foreach ver( split( fileVer ) ) {
  ver1 = eregmatch( pattern:"(.*)\nwifi.sys.?([0-9.]+)", string:ver );
  version = ver1[2];
  winPath = ver1[1];
  if( version_is_less( version:version, test_version:maxVer ) ) {
    continue;
  } else {
    maxVer = version;
  }
}

if(maxVer)
{
  if(version_is_less(version:maxVer, test_version:"6.0.6002.24202"))
  {
    report = report_fixed_ver(file_checked:winPath + "Nwifi.sys",
                              file_version:maxVer, vulnerable_range:"Less than 6.0.6002.24202");
    security_message(data:report);
    exit(0);
  }
}
exit(0);
