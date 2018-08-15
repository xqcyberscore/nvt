##############################################################################
# OpenVAS Vulnerability Test
# $Id: smb_registry_access.nasl 10958 2018-08-14 13:49:12Z cfischer $
#
# Check for SMB accessible registry
#
# Authors:
# Chandan S <schandan@secpod.com>
#
# Copyright:
# Copyright (C) 2008 SecPod, http://www.secpod.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
##############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10400");
  script_version("$Revision: 10958 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-14 15:49:12 +0200 (Tue, 14 Aug 2018) $");
  script_tag(name:"creation_date", value:"2008-09-10 10:22:48 +0200 (Wed, 10 Sep 2008)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_category(ACT_GATHER_INFO);
  script_family("Windows");
  script_name("Check for SMB accessible registry");
  script_copyright("Copyright (C) 2008 SecPod");
  # Don't add a dependency to os_detection.nasl. This will cause a dependency sycle.
  script_dependencies("netbios_name_get.nasl", "smb_login.nasl", "smb_nativelanman.nasl", "gb_windows_services_start.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/transport", "SMB/name", "SMB/login", "SMB/password");
  script_exclude_keys("SMB/samba");

  script_xref(name:"URL", value:"http://docs.greenbone.net/GSM-Manual/gos-3.1/en/scanning.html#requirements-on-target-systems-with-windows");
  script_xref(name:"URL", value:"http://docs.greenbone.net/GSM-Manual/gos-4/en/vulnerabilitymanagement.html#requirements-on-target-systems-with-windows");

  script_tag(name:"summary", value:"This routine checks if the registry can be accessed remotely via SMB using the login/password
  credentials. If the access is failing a warning is shown.");

  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include("smb_nt.inc");
include("host_details.inc");
include("misc_func.inc");
include("version_func.inc");

gos_version = get_local_gos_version();
if( ! strlen( gos_version ) > 0 ||
    version_is_less( version:gos_version, test_version:"4.2.4" ) ) {
  old_routine = TRUE;
}

if( kb_smb_is_samba() ) exit( 0 );

port = kb_smb_transport();
if( ! port ) port = 139;
if( ! get_port_state( port ) ) exit( 0 );

name = kb_smb_name();
if( ! name ) exit( 0 );

login = kb_smb_login();
pass  = kb_smb_password();
dom   = kb_smb_domain();

soc = open_sock_tcp( port );
if( ! soc ) exit( 0 );

r = smb_session_request( soc:soc, remote:name );
if( ! r ) {
  close( soc );
  exit( 0 );
}

prot = smb_neg_prot( soc:soc );
if( ! prot ) {
  close( soc );
  exit( 0 );
}

r = smb_session_setup( soc:soc, login:login, password:pass, domain:dom, prot:prot );
if( ! r ) {
  close( soc );
  exit( 0 );
}

uid = session_extract_uid( reply:r );
if( ! uid ) {
  close( soc );
  exit( 0 );
}

r = smb_tconx( soc:soc, name:name, uid:uid, share:"IPC$" );
if( ! r ) {
  close( soc );
  exit( 0 );
}

tid = tconx_extract_tid( reply:r );
if( ! tid ) {
  close( soc );
  exit( 0 );
}

message = 'It was not possible to connect to the PIPE\\winreg on the remote host. If you intend to use the Scanner to ' +
          'perform registry-based checks, the registry checks will not work because the \'Remote ' +
          'Registry\' service is not running or has been disabled on the remote host.' +
          '\n\nPlease either:\n' +
          '\n- configure the \'Startup Type\' of the \'Remote Registry\' service on the target host to \'Automatic\'.';

if( old_routine ) {
  message += '\n- configure the NVT \'Windows Services Start\' (OID: 1.3.6.1.4.1.25623.1.0.804786) to start this service automatically.';
}

startErrors = get_kb_list( "RemoteRegistry/Win/Service/Manual/Failed" );
if( startErrors ) {
  message += '\n- check the below error which might provide additional info.';
  message += '\n\nThe scanner tried to start the \'Remote Registry\' service but received the following errors:\n';
  foreach startError( startErrors ) {
    # Clean-up the logs from the wmiexec.py before reporting it to the end user
    startError = ereg_replace( string:startError, pattern:".*Impacket.*Core Security Technologies", replace:"" );
    message += startError + '\n';
  }
}

r = smbntcreatex( soc:soc, uid:uid, tid:tid, name:"\winreg" );
if( ! r ) {
  sleep( 3 ); # Makes sure that the service has enough time to start after the first request.
  # Second try as the remote service is not running after the first request if it
  # has the "Automatic (Trigger Start)" Startup Type set and the service wasn't running yet.
  r = smbntcreatex( soc:soc, uid:uid, tid:tid, name:"\winreg" );
  if( ! r ) {
    # Saved for later use in gb_win_lsc_authentication_info.nasl
    set_kb_item( name:"SMB/registry_access/error", value:message );
    log_message( port:0, data:message );
    close( soc );
    exit( 0 );
  }
}

pipe = smbntcreatex_extract_pipe( reply:r );
if( ! pipe ) {
  close( soc );
  exit( 0 );
}

r = pipe_accessible_registry( soc:soc, uid:uid, tid:tid, pipe:pipe );
close( soc );

if( ! r ) {
  # Saved for later use in gb_win_lsc_authentication_info.nasl
  set_kb_item( name:"SMB/registry_access/error", value:message );
  log_message( port:0, data:message );
} else {
  set_kb_item( name:"SMB/registry_access", value:TRUE );
  set_kb_item( name:"SMB_or_WMI/access_successful", value:TRUE );
}

exit( 0 );
