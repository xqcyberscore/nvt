###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_windows_services_start.nasl 6744 2017-07-17 18:03:32Z cfischer $
#
# Windows Services Start
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.804786");
  script_version("$Revision: 6744 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-07-17 20:03:32 +0200 (Mon, 17 Jul 2017) $");
  script_tag(name:"creation_date", value:"2014-11-04 16:38:25 +0530 (Tue, 04 Nov 2014)");
  script_name("Windows Services Start");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Windows");
  # Don't add a dependency to os_detection.nasl. This will cause a dependency sycle.
  script_dependencies("toolcheck.nasl", "smb_login.nasl", "smb_nativelanman.nasl", "netbios_name_get.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/login", "SMB/password", "Tools/Present/wmi");
  script_exclude_keys("SMB/samba");

  script_add_preference(name:"Automatically enable the Remote Registry service (please see NOTE)", type:"checkbox", value:"no");

  script_tag(name:"summary", value:"This routine starts not running (but required) windows services before launching an
  authenticated scan.

  NOTE: This plugin is using the 'win_cmd_exec' command from openvas-smb which is deploying a
  service 'winexesvc.exe' to the target system. Because of this the plugin is disabled by default
  to avoid modifications on the target system. Please see the script preferences on how to enable this.");

  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include("smb_nt.inc");

autostart_service = script_get_preference( "Automatically enable the Remote Registry service (please see NOTE)" );
if( autostart_service == "no" ) exit( 0 );

if( ! defined_func( "win_cmd_exec" ) ) exit( 0 );

function run_command( command, password, username ) {

  local_var command, password, username, serQueryRes, serStat;

  ## Run the Command and get the Response
  serQueryRes = win_cmd_exec( cmd:command, password:password, username:username );

  if( "Access is denied" >< serQueryRes ) {
    error_message( data:"SC Command Error: Access is denied." );
  }
  else if( "The specified service does not exist" >< serQueryRes ) {
    error_message( data:"SC Command Error: The specified service does not exist." );
  }
  else if( "The service cannot be started" >< serQueryRes && "it is disabled" >< serQueryRes ) {
    error_message( data:"SC Command Error: Unable to start the service, maybe it is set to 'Disabled'." );
  }
  else if( "OpenService FAILED" >< serQueryRes && "specified service does not exist" >< serQueryRes ) {
    error_message( data:"SC Command Error: The specified service does not exist." );
  }
  else if( "StartService FAILED" >< serQueryRes ) {
    error_message( data:"SC Command Error: Failed to start the service." );
  }
  else if( "An instance of the service is already running" >< serQueryRes ) {
    error_message( data:"SC Command Error: An instance of the service is already running." );
  }
  else {
    ## Confirm the "sc query" Response
    if( "SERVICE_NAME" >< serQueryRes && "STATE" >< serQueryRes && "SERVICE_EXIT_CODE" >< serQueryRes ) {
      ## Get the state of the service
      serStat = eregmatch( pattern:"STATE.*: [0-9]  ([a-zA-Z_]+)", string:serQueryRes );
      return serStat[1];
    }
  }
}

lanman = get_kb_item( "SMB/NativeLanManager" );
samba  = get_kb_item( "SMB/samba" );

if( samba || "samba" >< tolower( lanman ) ) exit( 0 );

port = kb_smb_transport();
if( ! port ) port = 139;
if( ! get_port_state( port ) ) exit( 0 );

username = kb_smb_login();
password = kb_smb_password();
if( ! username && ! password ) exit( 0 );

domain = kb_smb_domain();
if( domain ) username = domain + "/" + username;

service_list = make_list( "RemoteRegistry" );

foreach service( service_list ) {

  ## To get the status of the service
  cmd = "cmd /c sc query " + service;
  serQueryStat = run_command( command:cmd, password:password, username:username );

  ## Check wheather it is in stopped state
  if( "STOPPED" >< serQueryStat ) {
    ## To start the service
    cmd = "cmd /c sc start " + service;
    serQueryStat = run_command( command:cmd, password:password, username:username );

    ## Confirm wheather it is started or not
    if( "START_PENDING" >< serQueryStat ) {
      ## To get the status of the service
      cmd = "cmd /c sc query " + service;
      serQueryStat = run_command( command:cmd, password:password, username:username );

      if( "RUNNING" >< serQueryStat ) {
        ## set the kb if the service started
        set_kb_item( name:service + "/Win/Service/Manual/Start", value:TRUE );
      }
    }
  }
}

exit( 0 );