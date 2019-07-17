##############################################################################
# OpenVAS Vulnerability Test
#
# Login configurations
#
# Authors:
# Georges Dagousset <georges.dagousset@alert4web.com>
# HTTP code comes from http_auth.nasl written by Michel Arboi <arboi@alussinan.org>
# NNTP was added by Michel Arboi <arboi@alussinan.org>
#
# Copyright:
# Copyright (C) 2005 Georges Dagousset
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
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

default_http_login = "";
default_http_password = "";

default_nntp_login = "";
default_nntp_password = "";

default_ftp_login = "anonymous";
default_ftp_password = "anonymous@example.com";
default_ftp_w_dir = "/incoming";

default_pop2_login = "";
default_pop2_password = "";

default_pop3_login = "";
default_pop3_password = "";

default_imap_login = "";
default_imap_password = "";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10870");
  script_version("2019-07-08T14:12:44+0000");
  script_tag(name:"last_modification", value:"2019-07-08 14:12:44 +0000 (Mon, 08 Jul 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Login configurations"); # nb: Don't change the script name, this name is hardcoded within some manager functions...
  script_category(ACT_SETTINGS);
  script_copyright("This script is Copyright (C) 2005 Georges Dagousset");
  script_family("Settings");

  script_add_preference(name:"HTTP account :", type:"entry", value:default_http_login, id:2);
  script_add_preference(name:"HTTP password (sent in clear) :", type:"password", value:default_http_password, id:3);

  script_add_preference(name:"NNTP account :", type:"entry", value:default_nntp_login, id:4);
  script_add_preference(name:"NNTP password (sent in clear) :", type:"password", value:default_nntp_password, id:5);

  script_add_preference(name:"FTP account :", type:"entry", value:default_ftp_login, id:6);
  script_add_preference(name:"FTP password (sent in clear) :", type:"password", value:default_ftp_password, id:7);
  script_add_preference(name:"FTP writeable directory :", type:"entry", value:default_ftp_w_dir, id:8);

  script_add_preference(name:"POP2 account :", type:"entry", value:default_pop2_login, id:9);
  script_add_preference(name:"POP2 password (sent in clear) :", type:"password", value:default_pop2_password, id:10);

  script_add_preference(name:"POP3 account :", type:"entry", value:default_pop3_login, id:11);
  script_add_preference(name:"POP3 password (sent in clear) :", type:"password", value:default_pop3_password, id:12);

  script_add_preference(name:"IMAP account :", type:"entry", value:default_imap_login, id:13);
  script_add_preference(name:"IMAP password (sent in clear) :", type:"password", value:default_imap_password, id:14);

  script_add_preference(name:"Never send SMB credentials in clear text", type:"checkbox", value:"yes", id:15);
  script_add_preference(name:"Only use NTLMv2", type:"checkbox", value:"no", id:16);

  script_add_preference(name:"NTLMSSP", type:"checkbox", value:"yes", id:1); # nb: Don't change this name and id, these are hardcoded / used in GVMd

  script_tag(name:"summary", value:"Provide the username/password for the common servers :
  HTTP, FTP, NNTP, POP2, POP3, IMAP and SMB (NetBios).

  Some plugins will use those logins when needed.
  If you do not fill some logins, those plugins will not be able run.

  This plugin does not do any security check.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("misc_func.inc");

# HTTP
http_login = script_get_preference( "HTTP account :", id:2 );
http_password = script_get_preference( "HTTP password (sent in clear) :", id:3 );
if( http_login && http_password ) {
  set_kb_item( name:"http/login", value:http_login );
  set_kb_item( name:"http/password", value:http_password );

  userpass = string( http_login, ":", http_password );
  userpass64 = base64( str:userpass );
  authstr = "Authorization: Basic " + userpass64;
  set_kb_item( name:"http/auth", value:authstr );
}

# NNTP
nntp_login = script_get_preference( "NNTP account :", id:4 );
nntp_password = script_get_preference( "NNTP password (sent in clear) :", id:5 );
if( nntp_login && nntp_password ) {
  set_kb_item( name:"nntp/login", value:nntp_login );
  set_kb_item( name:"nntp/password", value:nntp_password );
}

# FTP
ftp_login = script_get_preference( "FTP account :", id:6 );
if( ! ftp_login ) ftp_login = default_ftp_login;

ftp_password = script_get_preference( "FTP password (sent in clear) :", id:7 );
if( ! ftp_password ) ftp_password = default_ftp_password;

ftp_w_dir = script_get_preference( "FTP writeable directory :", id:8 );
if( ! ftp_w_dir ) ftp_w_dir = default_ftp_w_dir;
set_kb_item(name:"ftp/writeable_dir", value:ftp_w_dir);

if( ftp_login && ftp_password ) {
  set_kb_item( name:"ftp/login", value:ftp_login );
  set_kb_item( name:"ftp/password", value:ftp_password );
}

# POP2
pop2_login = script_get_preference( "POP2 account :", id:9 );
pop2_password = script_get_preference( "POP2 password (sent in clear) :", id:10 );
if( pop2_login && pop2_password ) {
  set_kb_item( name:"pop2/login", value:pop2_login );
  set_kb_item( name:"pop2/password", value:pop2_password );
}

# POP3
pop3_login = script_get_preference( "POP3 account :", id:11 );
pop3_password = script_get_preference( "POP3 password (sent in clear) :", id:12 );
if( pop3_login && pop3_password ) {
  set_kb_item( name:"pop3/login", value:pop3_login );
  set_kb_item( name:"pop3/password", value:pop3_password );
}

# IMAP
imap_login = script_get_preference( "IMAP account :", id:13 );
imap_password = script_get_preference( "IMAP password (sent in clear) :", id:14 );
if( imap_login && imap_password ) {
  set_kb_item( name:"imap/login", value:imap_login );
  set_kb_item( name:"imap/password", value:imap_password );
}

# SMB
smb_ctxt = script_get_preference( "Never send SMB credentials in clear text", id:15 );
if( ! smb_ctxt ) smb_ctxt = "yes"; # Default from script preference

if( smb_ctxt == "yes" ) {
  set_kb_item( name:"SMB/dont_send_in_cleartext", value:TRUE );
}

smb_ntv1 = script_get_preference( "Only use NTLMv2", id:16 );
if( ! smb_ntv1 ) smb_ntv1 = "no"; # Default from script preference

if( smb_ntv1 == "yes" ) {
  set_kb_item( name:"SMB/dont_send_ntlmv1", value:TRUE );
  if( smb_ctxt != "yes" ) {
    set_kb_item( name:"SMB/dont_send_in_cleartext", value:TRUE );
  }
}

smb_ntlmssp = script_get_preference( "NTLMSSP", id:1 );
if( ! smb_ntlmssp ) smb_ntlmssp = "yes"; # Default from script preference

if( smb_ntlmssp == "yes" ) {
  set_kb_item( name:"SMB/NTLMSSP", value:TRUE );
}

exit( 0 );
