###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_seagate_nas_default_admin.nasl 5842 2017-04-03 13:15:19Z cfi $
#
# Seagate NAS Default Login
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

CPE = "cpe:/h:seagate:blackarmor_nas";

tag_summary = 'The remote Seagate NAS is prone to a default account
authentication bypass vulnerability.';

tag_impact = 'This issue may be exploited by a remote attacker to gain
access to sensitive information or modify system configuration.

Impact Level: Application';

tag_insight = 'It was possible to login with username "admin" and password "admin".';
tag_vuldetect = 'Try to login with admin/admin';
tag_solution = 'Change the password.';

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.103754"); 
 script_version("$Revision: 5842 $");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("Seagate NAS Default Login");

 script_tag(name:"last_modification", value:"$Date: 2017-04-03 15:15:19 +0200 (Mon, 03 Apr 2017) $");
 script_tag(name:"creation_date", value:"2013-08-08 14:02:06 +0200 (Thu, 08 Aug 2013)");
 script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
 script_family("Default Accounts");
 script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
 script_dependencies("gb_seagate_blackarmor_nas_detect.nasl");
 script_require_ports("Services/www", 80);
 script_mandatory_keys("seagate_nas/installed");

 script_tag(name : "summary" , value : tag_summary);
 script_tag(name : "impact" , value : tag_impact);
 script_tag(name : "vuldetect" , value : tag_vuldetect);
 script_tag(name : "insight" , value : tag_insight);
 script_tag(name : "solution" , value : tag_solution);

 exit(0);
}

include("http_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))exit(0);

url = "/index.php";
req = http_get(item:url, port:port);
buf = http_send_recv(port:port, data:req, bodyonly:FALSE);

if("<title>Seagate NAS" >!< buf || "Set-Cookie" >!< buf)exit(0);

co = eregmatch(pattern:'Set-Cookie: ([^\n\r]+)', string:buf);
if(isnull(co[1]))exit(0);

cookie = co[1];

host = http_host_name(port:port);

data = 'p_user=admin&p_pass=admin&lang=en&xx=1&loginnow=Login';
len = strlen(data);

req = 'POST / HTTP/1.1\r\n' + 
      'Host: ' + host + '\r\n' + 
      'User-Agent: ' + OPENVAS_HTTP_USER_AGENT + '\r\n' + 
      'Referer: http://' + host + '/?lang=en\r\n' + 
      'DNT: 1\r\n' + 
      'Cookie: ' + cookie + '\r\n' + 
      'Content-Type: application/x-www-form-urlencoded\r\n' + 
      'Content-Length: ' + len + '\r\n' + 
      '\r\n' + data;

result = http_send_recv(port:port, data:req, bodyonly:FALSE);      

req = 'GET /admin/system_status.php?lang=en&gi=sy002 HTTP/1.1\r\n' + 
      'Host: ' + host + '\r\n' +
      'User-Agent: ' + OPENVAS_HTTP_USER_AGENT + '\r\n' +
      'Referer: http://' + host + '/?lang=en\r\n' +
      'DNT: 1\r\n' +
      'Cookie: ' + cookie + '\r\n' + '\r\n';

buf = http_send_recv(port:port, data:req, bodyonly:TRUE);      

if(">Logout<" >< buf && ">System Status<" >< buf && "Admin Password" >< buf) {

  security_message(port:port);
  exit(0);

}  

exit(0);

