# Copyright (C) 2009 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.801110");
  script_version("2019-10-29T06:41:59+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-10-29 06:41:59 +0000 (Tue, 29 Oct 2019)");
  script_tag(name:"creation_date", value:"2009-10-08 08:22:29 +0200 (Thu, 08 Oct 2009)");
  script_name("Avast (Free / Business) AntiVirus Version Detection (Windows)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);

  script_tag(name:"summary", value:"Detects the installed version of Avast (Free / Business) AntiVirus
  on Windows.");

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

    if( ! appName || appName !~ "Avast (Free Antivirus|Business Security)" )
      continue;

    concluded  = "Registry-Key:   " + key + item + '\n';
    concluded += "DisplayName:    " + appName;
    location = "unknown";
    version = "unknown";

    loc = registry_get_sz( key:key + item, item:"InstallLocation" );
    if( loc )
      location = loc;

    if( vers = registry_get_sz( key:key + item, item:"DisplayVersion" ) ) {
      version = vers;
      concluded += '\nDisplayVersion: ' + vers;
    }

    set_kb_item( name:"avast/antivirus/detected", value:TRUE );

    if( appName == "Avast Free Antivirus" ) {
      set_kb_item( name:"avast/antivirus_free/detected", value:TRUE );
    }
    else if( appName == "Avast Business Security" ) {
      set_kb_item( name:"avast/antivirus_business/detected", value:TRUE );
    }

    register_and_report_cpe( app:appName, ver:version, concluded:concluded,
                             base:"cpe:/a:avast:antivirus:", expr:"^([0-9.]+)", insloc:location, regService:"smb-login", regPort:0 );
    exit( 0 );
  }
}

exit( 0 );
