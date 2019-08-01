# Copyright (C) 2019 Greenbone Networks GmbH
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107634");
  script_version("2019-07-31T08:50:55+0000");
  script_tag(name:"last_modification", value:"2019-07-31 08:50:55 +0000 (Wed, 31 Jul 2019)");
  script_tag(name:"creation_date", value:"2019-04-05 14:14:06 +0200 (Fri, 05 Apr 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("FinalWire Ltd. AIDA64 Detection (Windows)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);

  script_tag(name:"summary", value:"Detects the installed version
  of FinalWire Ltd. AIDA64 for Windows.");
  script_xref(name:"URL", value:"http://www.aida64.com");
  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include( "smb_nt.inc" );
include( "cpe.inc" );
include( "host_details.inc" );
include( "secpod_smb_func.inc" );

os_arch = get_kb_item( "SMB/Windows/Arch" );
if( ! os_arch )
  exit( 0 );

if( "x86" >< os_arch ) {
  key_list = make_list( "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\" );
} else if( "x64" >< os_arch ) {
  key_list = make_list( "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\",
                        "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\" );
}

if( isnull( key_list ) )
  exit( 0 );

foreach key( key_list ) {
  foreach item( registry_enum_keys( key:key ) ) {

    appName = registry_get_sz( key:key + item, item:"DisplayName" );
    if( ! appName || appName !~ "AIDA64 (Extreme|Engineer|Business|Network Audit) [a-zA_Z0-9.]+" )
      continue;

    pub = registry_get_sz( key:key + item, item:"Publisher" );
    if( ! pub || pub !~ "FinalWire Ltd." )
      continue;

    concluded  = "Registry-Key:   " + key + item + '\n';
    concluded += "DisplayName:    " + appName;
    location = "unknown";
    version = "unknown";

    regversion = registry_get_sz( key:key + item, item:"DisplayVersion" );
    if( regversion )
      concluded += '\nDisplayVersion: ' + regversion;

    loc = registry_get_sz( key:key + item, item:"InstallLocation" );
    if( loc ) {
      location = loc;

      # nb: registry item 'DisplayVersion' not usable. Published vulnerability reports target fileversion.
      file = "aida64.exe";
      vers = fetch_file_version( sysPath:location, file_name:file );
      if( vers && vers =~ "^[0-9.]{3,}" ) {
        version = vers;
        concluded += '\nFileversion:    ' + vers + ' fetched from ' + location + file;
      }
    }

    set_kb_item( name:"finalwire/aida64/detected", value:TRUE );

    register_and_report_cpe( app:pub + " " + appName, ver:version, concluded:concluded,
                             base:"cpe:/a:finalwire:aida64:", expr:"^([0-9.]+)",
                             insloc:location, regService:"smb-login", regPort:0 );
    exit( 0 );
  }
}

exit( 0 );
