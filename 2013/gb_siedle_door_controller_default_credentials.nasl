###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_siedle_door_controller_default_credentials.nasl 6115 2017-05-12 09:03:25Z teissa $
#
# Siedle Door Controller Default Password
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
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

tag_summary = "The remote Siedle Door Controller is prone to a default account
authentication bypass vulnerability";

tag_insight = 'It was possible to login with username "Service" and password "Siedle".';

tag_impact = 'The "Service" account has a default password of "Siedle" which gives almost
full access to the system like adding, renaming, or deleting doors and users, and force all
the doors open';

tag_solution = "Change the password or contact your vendor for an update.";
tag_vuldetect = 'This check tries to login into the remote Siedle Door Controller.';

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103820";

if (description)
{
 script_oid(SCRIPT_OID);
 script_version ("$Revision: 6115 $");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

 script_name("Siedle Door Controller Default Password");


 script_tag(name:"last_modification", value:"$Date: 2017-05-12 11:03:25 +0200 (Fri, 12 May 2017) $");
 script_tag(name:"creation_date", value:"2013-10-24 10:01:48 +0100 (Thu, 24 Oct 2013)");
 script_category(ACT_ATTACK);
 script_tag(name:"qod_type", value:"remote_vul");
 script_family("Default Accounts");
 script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
 script_dependencies("gb_get_http_banner.nasl");
 script_require_ports("Services/www", 80);
 script_mandatory_keys("Z-World_Rabbit/banner");

 script_tag(name : "impact" , value : tag_impact);
 script_tag(name : "vuldetect" , value : tag_vuldetect);
 script_tag(name : "insight" , value : tag_insight);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);

 exit(0);

}

include("http_func.inc");
include("misc_func.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

banner = get_http_banner(port:port);
if("Server: Z-World Rabbit" >!< banner)exit(0);

host = get_host_name();

url = '/login.zht';
req = http_get(item:url, port:port);
buf = http_send_recv(port:port, data:req, bodyonly:FALSE);

if("Siedle" >!< buf)exit(0);

req = 'POST /login.cgi HTTP/1.1\r\n' +
      'Host: ' + host + '\r\n' +
      'Referer: http://' + host + '/login.zht\r\n' +
      'Content-Type: application/x-www-form-urlencoded\r\n' +
      'Content-Length: 125\r\n' +
      '\r\n' +
      'm_webdata.m_cgiLogin.m_user=Service&m_webdata.m_cgiLogin.m_passwd=Siedle&m_webdata.m_cgiLogin.m_lang=en&action.x=0&action.y=0';

buf = http_send_recv(port:port, data:req, bodyonly:FALSE);
if("Set-Cookie" >!< buf)exit(0);

cookie = eregmatch(pattern:'Set-Cookie: ([^\r\n]+)', string:buf);
if(isnull(cookie[1]))exit(0);
co = cookie[1];

req = 'GET /cfg/usrlist.zht HTTP/1.1\r\n' + 
      'Host: ' + host + '\r\n' + 
      'Cookie: ' + co + '\r\n\r\n';

buf = http_send_recv(port:port, data:req, bodyonly:FALSE);

if(buf =~ "HTTP/1.. 200" && "usrlist.name" >< buf) {
  security_message(port:port);
  exit(0);
}  

exit(99);

