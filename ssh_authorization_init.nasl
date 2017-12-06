##############################################################################
# OpenVAS Vulnerability Test
# $Id: ssh_authorization_init.nasl 7993 2017-12-05 09:04:08Z cfischer $
#
# This script allows to set SSH credentials for target hosts.
#
# Authors:
# Jan-Oliver Wagner <jan-oliver.wagner@greenbone.net>
# Felix Wolfsteller <felix.wolfsteller@greenbone.net>
# Chandrashekhar B <bchandra@secpod.com>
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2007,2008,2009,2010,2011,2012 Greenbone Networks GmbH
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
#
##############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103591");
  script_version("$Revision: 7993 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-05 10:04:08 +0100 (Tue, 05 Dec 2017) $");
  script_tag(name:"creation_date", value:"2012-10-24 10:55:52 +0100 (Wed, 24 Oct 2012)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("SSH Authorization"); # nb: Don't change the script name, this name is hardcoded within some manager functions...
  script_category(ACT_SETTINGS);
  script_copyright("Copyright 2007-2012 Greenbone Networks GmbH");
  script_family("Credentials");

  # Don't change the preference names, those names are hardcoded within some manager functions...

  # Preference type to trigger client-side ssh-login selection per target
  script_add_preference(name:"Keys:", type:"sshlogin", value:"-");
  script_add_preference(name:"SSH login name:", type:"entry", value:"");
  script_add_preference(name:"SSH password (unsafe!):", type:"password", value:"");
  script_add_preference(name:"SSH public key:", type:"file", value:"");
  script_add_preference(name:"SSH private key:", type:"file", value:"");
  script_add_preference(name:"SSH key passphrase:", type:"password", value:"");

  script_tag(name:"summary", value:"This script allows users to enter the information
  required to authorize and login via ssh protocol.

  These data will be used by other tests to executed authenticated checks.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

ssh_login_name     = script_get_preference( "SSH login name:" );
ssh_password       = script_get_preference( "SSH password (unsafe!):" );
ssh_public_key     = script_get_preference_file_content( "SSH public key:" );
ssh_private_key    = script_get_preference_file_content( "SSH private key:" );
ssh_key_passphrase = script_get_preference( "SSH key passphrase:" );

if( ssh_login_name )     set_kb_item( name:"Secret/SSH/login", value:ssh_login_name );
if( ssh_password )       set_kb_item( name:"Secret/SSH/password", value:ssh_password );
if( ssh_public_key )     set_kb_item( name:"Secret/SSH/publickey", value:ssh_public_key );
if( ssh_private_key )    set_kb_item( name:"Secret/SSH/privatekey", value:ssh_private_key );
if( ssh_key_passphrase ) set_kb_item( name:"Secret/SSH/passphrase", value:ssh_key_passphrase );

exit( 0 );
