###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wago_51598.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# WAGO Multiple Remote Vulnerabilities
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

tag_summary = "WAGO is prone to multiple security vulnerabilities, including:

1. A security-bypass vulnerability
2. Multiple information-disclosure vulnerabilities
3. A cross-site request forgery vulnerability

Successful attacks can allow an attacker to obtain sensitive
information, bypass certain security restrictions, and perform
unauthorized administrative actions.";

if (description)
{
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/51598");
 script_xref(name : "URL" , value : "http://dsecrg.com/pages/vul/show.php?id=401");
 script_xref(name : "URL" , value : "http://dsecrg.com/pages/vul/show.php?id=402");
 script_xref(name : "URL" , value : "http://dsecrg.com/pages/vul/show.php?id=403");
 script_xref(name : "URL" , value : "http://dsecrg.com/pages/vul/show.php?id=404");
 script_xref(name : "URL" , value : "http://www.wago.com/");
 script_oid("1.3.6.1.4.1.25623.1.0.103396");
 script_bugtraq_id(51598);
 script_version ("$Revision: 9352 $");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

 script_name("WAGO Multiple Remote Vulnerabilities");

 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2012-01-23 15:14:54 +0100 (Mon, 23 Jan 2012)");
 script_category(ACT_ATTACK);
 script_tag(name:"qod_type", value:"remote_vul");
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "summary" , value : tag_summary);
 exit(0); 
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("misc_func.inc");
   
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

url = string("/webserv/index.ssi"); 

if(http_vuln_check(port:port, url:url,pattern:"WAGO Ethernet Web-Based Management")) {

  default_credentials = make_list("admin:wago","user:user","guest:guest");

  foreach credential (default_credentials) {

    userpass64 = base64(str:credential);

    url = "/webserv/cplcfg/security.ssi";

    req = string("GET ", url," HTTP/1.1\r\n",
                 "Host: ", get_host_name(),"\r\n",
                 "Authorization: Basic ",userpass64,"\r\n",
                 "\r\n");

    buf = http_keepalive_send_recv(port:port, data:req);

    if("<caption>Webserver Security" >< buf && "Webserver and FTP User configuration" >< buf) {

        desc = string("It was possible to login with the following credentials\n\nURL:User:Password\n\n",url,":",credential,"\n");

        security_message(port:port,data:desc);
        exit(0);

    }

  }  
     
}

exit(0);
