##############################################################################
# OpenVAS Vulnerability Test
# $Id: smb_registry_access.nasl 5476 2017-03-03 11:06:36Z cfi $
#
# SMB accessible registry 
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
  script_version("$Revision: 5476 $");
  script_tag(name:"last_modification", value:"$Date: 2017-03-03 12:06:36 +0100 (Fri, 03 Mar 2017) $");
  script_tag(name:"creation_date", value:"2008-09-10 10:22:48 +0200 (Wed, 10 Sep 2008)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_category(ACT_GATHER_INFO);
  script_family("Windows");
  script_name("SMB accessible registry");
  script_copyright("Copyright (C) 2008 SecPod");
  # Don't add a dependency to os_detection.nasl. This will cause a dependency sycle.
  script_dependencies("netbios_name_get.nasl", "smb_login.nasl", "smb_nativelanman.nasl",
                      "gb_windows_services_start.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/transport", "SMB/name", "SMB/login", "SMB/password");
  script_exclude_keys("SMB/samba");

  script_tag(name:"summary" , value :"The remote registry can be accessed remotely using the login/password 
  credentials.");

  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include("smb_nt.inc");
include("host_details.inc");
 
lanman = get_kb_item( "SMB/NativeLanManager" );
samba  = get_kb_item( "SMB/samba" );

if( samba || "samba" >< tolower( lanman ) ) exit( 0 );

port = kb_smb_transport();
if( ! port ) port = 139;
if( ! get_port_state( port ) ) exit(0);

name = kb_smb_name();
if( ! name ) exit( 0 );

login = kb_smb_login();
pass  = kb_smb_password();

if( ! login ) login = "";
if( ! pass )  pass = "";

dom = kb_smb_domain();
	  
soc = open_sock_tcp( port );
if( ! soc ) exit( 0 );

 r = smb_session_request(soc:soc,  remote:name);
 if(!r){
	close(soc);
	exit(0);
 }

 prot = smb_neg_prot(soc:soc);
 if(!prot){
	close(soc);
	exit(0);
 }

 r = smb_session_setup(soc:soc, login:login, password:pass, domain:dom, prot:prot);
 if(!r){
	close(soc);
	exit(0);
 }

 uid = session_extract_uid(reply:r);
 if(!uid)
 {
   close(soc);
   exit(0);
 }

 r = smb_tconx(soc:soc, name:name, uid:uid, share:"IPC$");
 if(!r){
	close(soc);
	exit(0);
 }

 tid = tconx_extract_tid(reply:r);
 if(!tid){
	close(soc);
	exit(0);
 }

 r = smbntcreatex(soc:soc, uid:uid, tid:tid, name:"\winreg");
 if(!r)
 {
        close(soc);
        exit(0);
 }

 pipe = smbntcreatex_extract_pipe(reply:r);
 if (!pipe)
 {
        close(soc);
        exit(0);
 }

 r = pipe_accessible_registry(soc:soc, uid:uid, tid:tid, pipe:pipe);
 close(soc);

 if(!r)
 {
	log_message(data:"It was not possible to connect to PIPE\winreg on "+
                           "the remote host. If you\nintend to use OpenVAS to "+
                           "perform registry-based checks, the registry "+
                           "checks\nwill not work because the 'Remote "+
                           "Registry Access' service (winreg) has been\n" +
                           "disabled on the remote host");
        exit(0);
 }

 else
 {
	set_kb_item(name:"SMB/registry_access", value:TRUE);
        set_kb_item(name:"SMB/registry_full_access", value:TRUE);
 }
