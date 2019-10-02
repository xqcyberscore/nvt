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
  script_oid("1.3.6.1.4.1.25623.1.0.107578");
  script_version("2019-09-27T05:35:08+0000");
  script_tag(name:"last_modification", value:"2019-09-27 05:35:08 +0000 (Fri, 27 Sep 2019)");
  script_tag(name:"creation_date", value:"2019-02-16 13:26:35 +0100 (Sat, 16 Feb 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Siemens Automation License Manager Version Detection (Windows)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);

  script_tag(name:"summary", value:"Detects the installed version
  of Siemens Automation License Manager for Windows.");

  script_xref(name:"URL", value:"https://w3.siemens.com/mcms/process-control-systems/en/distributed-control-system-simatic-pcs-7/simatic-pcs-7-system-components/System-Administration/Pages/Automation-License-Manager.aspx");

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

    if( ! appName || appName !~ "Siemens Automation License Manager V[0-9.]+" )
      continue;

    concluded  = "Registry-Key:   " + key + item + '\n';
    concluded += "DisplayName:    " + appName;
    location = "unknown";
    version = "unknown";

    loc = registry_get_sz( key:key + item, item:"InstallLocation" );
    if( loc )
      location = loc;

    if( regvers = registry_get_sz( key:key + item, item:"DisplayVersion" ) ) {
      concluded += '\nDisplayVersion: ' + regvers;
      v_build = eregmatch( pattern:"V([0-9.]+)[ \+]*(SP([0-9]+))?[ \+]*(Upd([0-9]+))?", string:appName );
      if( v_build[2] == '' ) v_build[2] = 'SP0';
      if( v_build[3] == '' ) v_build[3] = '0';
      if( v_build[4] == '' ) v_build[4] = 'Upd0';
      if( v_build[5] == '' ) v_build[5] = '0';
      version = v_build[1] + '.' + v_build[3] + '.' + v_build[5];
      concluded += '\nDerived Version ' + version + ' from RegKey "DisplayName"';
      concluded += '\nServicepack:    ' + v_build[2];
      concluded += '\nUpdate:         ' + v_build[4];
    }

    set_kb_item( name:"siemens/automation_license_manager/detected", value:TRUE );

    register_and_report_cpe( app:appName, ver:version, concluded:concluded,
                             base:"cpe:/a:siemens:automation_license_manager:", expr:"^([0-9.]+)", insloc:location, regService:"smb-login", regPort:0 );
    exit( 0 );
  }
}

exit( 0 );
