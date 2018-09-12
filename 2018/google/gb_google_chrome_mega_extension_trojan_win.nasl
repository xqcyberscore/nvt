##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_google_chrome_mega_extension_trojan_win.nasl 11350 2018-09-12 08:17:35Z santu $
#
# Google Chrome MEGA Extension Trojan-Windows
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
  script_oid("1.3.6.1.4.1.25623.1.0.813789");
  script_version("$Revision: 11350 $");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-09-12 10:17:35 +0200 (Wed, 12 Sep 2018) $");
  script_tag(name:"creation_date", value:"2018-09-10 12:21:10 +0530 (Mon, 10 Sep 2018)");
  script_name("Google Chrome MEGA Extension Trojan-Windows");

  script_tag(name:"summary", value:"This host is installed with MEGA extension
  for Google Chrome and tries to detect the trojaned MEGA extension.");

  script_tag(name:"vuldetect", value:"Check if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists as a trojaned version of
  MEGA extension was available in google-chrome webstore for installation and
  update.");

  script_tag(name:"impact", value:"Upon installation or auto update to trojaned
  version, extension would exfiltrate credentials for sites including amazon.com,
  live.com, github.com, google.com (or webstore login), myetherwallet.com,
  mymonero.com, idex.market and HTTP POST requests to any other sites. Then it
  will send them to a server located in Ukraine.

  Impact Level: Application");

  script_tag(name:"affected", value:"MEGA extension version 3.39.4 for Chrome on Windows");

  script_tag(name:"solution", value:"Upgrade to MEGA extension version 3.39.5
  or later. For updates refer to Reference links.");

  script_tag(name:"solution_type", value:"VendorFix");

  # Version information available under path to mega.html
  script_tag(name:"qod", value:"75");

  script_xref(name:"URL", value:"https://thehackernews.com/2018/09/mega-file-upload-chrome-extension.html");
  script_xref(name:"URL", value:"https://mega.nz");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_google_chrome_detect_portable_win.nasl", "smb_reg_service_pack.nasl", "gb_wmi_access.nasl");
  script_mandatory_keys("GoogleChrome/Win/Ver", "WMI/access_successful", "SMB/WindowsVersion");
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
        + raw_string(0x22) + 'Mega' + raw_string(0x22) + ' AND Extension ='
        + raw_string(0x22) + 'html' + raw_string(0x22);
fileVer1 = wmi_query( wmi_handle:handle, query:query1);
if(!fileVer1){
  exit(0);
}

foreach ver(split( fileVer1 ))
{
  ver = eregmatch(pattern:"(.*(g|G)oogle.(c|C)hrome.*(e|E)xtensions.[A-za-z]+\\([0-9._]+)\\(M|m)ega\\html)\\mega.html", string:ver);
  if(!ver[5]){
    continue;
  }
  version = ver[5];
  filePath = ver[1];
  if(version && version_is_equal(version:version, test_version:"3.39.4"))
  {
    report = report_fixed_ver(installed_version:version, fixed_version:"3.39.5", install_path:filePath);
    security_message(data:report);
    exit(0);
  }
}
exit(0);
