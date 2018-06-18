###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_utorrent_detect_portable_win.nasl 10208 2018-06-15 07:53:13Z cfischer $
#
# uTorrent Portable Version Detection (Windows)
#
# Authors:
# Thorsten Passfeld <thorsten.passfeld@greenbone.net>
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
  script_oid("1.3.6.1.4.1.25623.1.0.114008");
  script_version("$Revision: 10208 $");
  script_tag(name:"last_modification", value:"$Date: 2018-06-15 09:53:13 +0200 (Fri, 15 Jun 2018) $");
  script_tag(name:"creation_date", value:"2018-04-24 17:24:16 +0200 (Tue, 24 Apr 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("uTorrent Portable Version Detection (Windows)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  # uTorrent dependency was added so we don't detect a registry-based installation twice
  script_dependencies("gb_utorrent_detect_win.nasl", "gb_wmi_access.nasl");
  script_mandatory_keys("win/lsc/search_portable_apps", "WMI/access_successful");

  script_tag(name:"summary", value:"Detection of uTorrent Portable on Windows.

  The script logs in via WMI, searches for uTorrent executables on the filesystem
  and gets the installed version if found.

  To enable the search for this product you need to 'Enable Detection of Portable Apps on Windows'
  in the Options for Local Security Checks (OID: 1.3.6.1.4.1.25623.1.0.100509) of your scan config.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("wmi_file.inc");
include("misc_func.inc");
include("cpe.inc");
include("host_details.inc");
include("smb_nt.inc");

host    = get_host_ip();
usrname = kb_smb_login();
passwd  = kb_smb_password();

if( ! host || ! usrname || ! passwd ) exit( 0 );

domain = kb_smb_domain();
if( domain ) usrname = domain + '\\' + usrname;

handle = wmi_connect( host:host, username:usrname, password:passwd );
if( ! handle ) exit( 0 );

fileList = wmi_file_file_search( handle:handle, fileName:"utorrent", fileExtn:"exe" );
if( ! fileList ) {
  wmi_close( wmi_handle:handle );
  exit( 0 );
}

# From gb_utorrent_detect_win.nasl to avoid a doubled detection of
# a registry-based installation.
detectedList = get_kb_list( "uTorrent/Win/InstallLocations" );

fileList = split( fileList, keep:FALSE );
foreach filePath( fileList ) {

  if( filePath == "Name" ) continue; # Just ignore the header of the list...

  # wmi_file_file_search returns the .exe filename so we're stripping it away
  # to keep the install location registration the same way like in gb_utorrent_detect_win.nasl
  location = filePath - "\utorrent.exe";
  if( detectedList && in_array( search:tolower( location ), array:detectedList ) ) continue; # We already have detected this installation...

  # nb: wmi_file_fileversion needs doubled backslash in the path but
  # wmi_file_file_search returns single backslash in the path...
  filePath = ereg_replace( pattern:"\\", replace:"\\", string:filePath );

  versList = wmi_file_fileversion( handle:handle, filePath:filePath );
  versList = split( versList, keep:FALSE );
  foreach vers( versList ) {

    if( vers == "Version" ) continue; # Just ignore the header of the list...

    # Version of the uTorrent.exe file is something like 3.5.3.44352
    # so we need to catch the first four parts of the version.
    if( vers && version = eregmatch( string:vers, pattern:"^([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)" ) ) {

      set_kb_item( name:"uTorrent/Win/InstallLocations", value:tolower( location ) );
      set_kb_item( name:"uTorrent/Win/Version", value:version[1] );

      cpe = "cpe:/a:bittorrent:utorrent:";

      register_and_report_cpe( app:"uTorrent Portable", ver:version[1], concluded:vers, base:cpe, expr:"^([0-9.]+)", insloc:location );
    }
  }
}

wmi_close( wmi_handle:handle );

exit( 0 );
