###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_flash_player_plugin_detect_win.nasl 10161 2018-06-12 10:21:02Z asteins $
#
# Adobe Flash Player Plugin Version Detection (Windows)
#
# Authors:
# Michael Martin <michael.martin@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, https://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107320");
  script_version("$Revision: 10161 $");
  script_tag(name:"last_modification", value:"$Date: 2018-06-12 12:21:02 +0200 (Tue, 12 Jun 2018) $");
  script_tag(name:"creation_date", value:"2018-04-24 11:23:58 +0200 (Tue, 24 Apr 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Adobe Flash Player Plugin Version Detection (Windows)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_wmi_access.nasl");
  script_mandatory_keys("win/lsc/search_portable_apps", "WMI/access_successful");

  script_tag(name:"summary", value:"Detection of Adobe Flash Player Plugin on Windows.

  The script logs in via WMI, searches for Adobe Flash Player Plugins on the filesystem
  and gets the installed version if found.

  To enable the search for portable versions of this product you need to 'Enable Detection
  of Portable Apps on Windows' in the Options for Local Security Checks
  (OID: 1.3.6.1.4.1.25623.1.0.100509) of your scan config.");

  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include("wmi_file.inc");
include("misc_func.inc");
include("cpe.inc");
include("host_details.inc");
include("smb_nt.inc");
include("version_func.inc");

host    = get_host_ip();
usrname = kb_smb_login();
passwd  = kb_smb_password();
if( ! host || ! usrname || ! passwd ) exit( 0 );

domain = kb_smb_domain();
if( domain ) usrname = domain + '\\' + usrname;

handle = wmi_connect( host:host, username:usrname, password:passwd );
if( ! handle ) exit( 0 );

query = "SELECT Name, FileName, Path from CIM_DataFile Where FileName LIKE 'NPSWF%' and Extension = 'dll'";

fileList = wmi_query(wmi_handle:handle, query:query);

if( fileList ){
  files = split (fileList, keep:FALSE );

  foreach file ( files ) {
    if(file == "FileName|Name|Path" ) continue;

    file_split = split (file, sep:"|", keep:FALSE );
    filename = file_split[0];

    version_split = split(filename, sep:"_", keep:FALSE);
    version = version_split[1]+ "." +version_split[2]+ "." +version_split[3] + "." +version_split[4];
    location = "c:" +file_split[2];

    if ( version && version =~ "^([0-9.]+)" ) {
      set_kb_item( name:"AdobeFlashPlayer/Win/InstallLocations", value:tolower( location ) );
      set_kb_item( name:"AdobeFlashPlayer/Win/Installed", value:TRUE );

      if ("system32" >< location) {
        base = "cpe:/a:adobe:flash_player:x64:";
        app = "Adobe Flash Player Plugin 64bit";
      } else if ("syswow64" >< location) {
        base = "cpe:/a:adobe:flash_player:";
        app = "Adobe Flash Player Plugin 32bit";
      } else if ("NPSWF64" >< filename) {
        base = "cpe:/a:adobe:flash_player:x64:";
        app = "Adobe Flash Player Plugin 64bit Portable";
      } else {
        base = "cpe:/a:adobe:flash_player:";
        app = "Adobe Flash Player Plugin 32bit Portable";
      }

      register_and_report_cpe( app:app, ver:version, base:base, expr:"^([0-9.]+)", insloc:location );
    }
  }
}

wmi_close( wmi_handle:handle );
exit( 0 );
