# Copyright (C) 2010 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.801289");
  script_version("2019-08-30T09:54:50+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-08-30 09:54:50 +0000 (Fri, 30 Aug 2019)");
  script_tag(name:"creation_date", value:"2010-09-21 16:43:08 +0200 (Tue, 21 Sep 2010)");
  script_name("TortoiseSVN Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);

  script_tag(name:"summary", value:"Detects the installed version of TortoiseSVN on Windows.

  The script logs in via smb, searches for TortoiseSVN in the registry and gets the version.");

  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include( "smb_nt.inc" );
include( "secpod_smb_func.inc" );
include( "cpe.inc" );
include( "host_details.inc" );

if( ! registry_key_exists( key:"SOFTWARE\TortoiseSVN\" ) ) {
  exit( 0 );
}

os_arch = get_kb_item( "SMB/Windows/Arch" );
if( ! os_arch ) {
  exit( 0 );
}

# 32bit app can't be installed on 64bit OS. The 32bit installer on a
# 64bit OS will just quit the installation process.
key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if( ! registry_key_exists( key:key ) ) {
  exit( 0 );
}

foreach item( registry_enum_keys( key:key ) ) {
  appName = registry_get_sz( key:key + item, item:"DisplayName" );
  if( ! appName || appName !~ "TortoiseSVN" )
    continue;

  concluded  = "Registry-Key:   " + key + item + '\n';
  concluded += "DisplayName:    " + appName;
  location = "unknown";
  version = "unknown";

  if( vers = registry_get_sz( key:key + item, item:"DisplayVersion" ) ) {
    regvers = vers;
    concluded += '\nDIsplayVersion: ' + regvers;
    versionmatch = eregmatch( string:appName, pattern:"([0-9]+\.[0-9]+\.[0-9])+" );
    version = versionmatch[0];
    # nb. Done to match versions mentioned in advisories.
    concluded += '\nVersion: ' + version + ' ' + 'extracted from registry key-value "DisplayName"';
  }

  loc = registry_get_sz( key:key + item, item:"InstallLocation" );
  if( loc )
    location = loc;

  set_kb_item( name:"tortoisesvn/detected", value:TRUE );

  if( "64" >< os_arch ) {
    cpe_old = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:tigris:tortoisesvn:x64:" );
    if( ! cpe_old )
      cpe_old = "cpe:/a:tigris:tortoisesvn:x64";
    register_product( cpe:cpe_old, location:location, service:"smb-login" );

    cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:tortoisesvn:tortoisesvn:x64:" );
    if( ! cpe )
      cpe = "cpe:/a:tortoisesvn:tortoisesvn:x64";
    register_product( cpe:cpe, location:location, service:"smb-login" );

  } else {
    cpe_old = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:tigris:tortoisesvn:" );
    if( ! cpe_old )
      cpe_old = "cpe:/a:tigris:tortoisesvn";
    register_product( cpe:cpe_old, location:location, service:"smb-login");

    cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:tortoisesvn:tortoisesvn:" );
    if( ! cpe )
      cpe = "cpe:/a:tortoisesvn:tortoisesvn";
    register_product( cpe:cpe, location:location, service:"smb-login");

  }

  log_message( data:build_detection_report( app:appName, version:version, install:location, cpe:cpe, concluded:concluded ),
               port:0 );
  exit( 0 );
}

exit( 0 );