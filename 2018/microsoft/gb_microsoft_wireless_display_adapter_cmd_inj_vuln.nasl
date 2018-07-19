###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_microsoft_wireless_display_adapter_cmd_inj_vuln.nasl 10540 2018-07-19 07:26:13Z santu $
#
# Microsoft Wireless Display Adapter Command Injection Vulnerability
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.813702");
  script_version("$Revision: 10540 $");
  script_cve_id("CVE-2018-8306");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-07-19 09:26:13 +0200 (Thu, 19 Jul 2018) $");
  script_tag(name:"creation_date", value:"2018-07-17 15:16:38 +0530 (Tue, 17 Jul 2018)");
  script_name("Microsoft Wireless Display Adapter Command Injection Vulnerability");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Advisory for CVE-2018-8306.");

  script_tag(name:"vuldetect", value:"Get the vulnerable file version and
  check appropriate patch is applied or not.");

  script_tag(name:"insight", value:"The flaw exists due to an error when the
  Microsoft Wireless Display Adapter does not properly manage user input.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to send administrative commands to the MWDA, including commands with illegal
  characters which could cause the MWDA to stop functioning correctly.

  Impact Level: Application");

  script_tag(name:"affected", value:"Microsoft Wireless Display Adapter V2
  Software Version 2.0.8350, 2.0.8365 and 2.0.8372");

  script_tag(name:"solution", value:"Run Windows Update and update the
  listed hotfixes or download and update mentioned hotfixes in the advisory
  from the Reference link.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name : "URL" , value : "https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2018-8306");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Windows");
  script_dependencies("secpod_reg_enum.nasl", "gb_wmi_access.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "WMI/access_successful");
  script_require_ports(139, 445);
  exit(0);
}

include("secpod_reg.inc");
include("smb_nt.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win10:1, win10x64:1) <= 0){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Appx" ;
storelocation = registry_get_sz(key:key, item:"PackageRoot");

if(storelocation){
  mailPath = storelocation ;
} else {
  exit(0);
}

host    = get_host_ip();
usrname = get_kb_item( "SMB/login" );
passwd  = get_kb_item( "SMB/password" );
if( !host || !usrname || !passwd ) exit(0);

domain  = get_kb_item( "SMB/domain" );
if(domain) usrname = domain + '\\' + usrname;

handle = wmi_connect( host:host, username:usrname, password:passwd );

if( ! handle ) exit( 0 );

query = 'Select Version from CIM_DataFile Where FileName ='
        + raw_string(0x22) + 'wirelessdisplayadapter' + raw_string(0x22)
        + ' AND Extension =' + raw_string(0x22) + 'dll' + raw_string(0x22);

fileVer = wmi_query( wmi_handle:handle, query:query);
foreach ver(split(fileVer))
{
  if( ver == "Version" ) continue;

  if((tolower(mailPath) >< ver) || (mailPath >< ver))
  {
    ver = eregmatch(pattern:"(.*wirelessdisplayadapter.*)wirelessdisplayadapter.dll.([0-9.]+)", string:ver);
    if(!ver[2]){
      continue;
    }
    version = ver[2];
    if(ver[1]){
      filePath = ver[1];
    } else {
      filePath = "Unknown" ;
    }

    if(version_is_less(version:version, test_version:"3.0.124.0"))
    {
      report = report_fixed_ver(installed_version:version, fixed_version:"3.0.124.0", install_path:filePath);
      security_message(data:report);
      wmi_close( wmi_handle:handle );
      exit(0);
    }
  }
}
wmi_close( wmi_handle:handle );
exit(0);
