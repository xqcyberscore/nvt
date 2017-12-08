# OpenVAS Vulnerability Test
# $Id: exchange_public_folders_information_leak.nasl 8023 2017-12-07 08:36:26Z teissa $
# Description: Microsoft Exchange Public Folders Information Leak
#
# Authors:
# Noam Rathaus <noamr@securiteam.com>
#
# Copyright:
# Copyright (C) 2000 Noam Rathaus <noamr@securiteam.com>
# Copyright (C) 2001 SecuriTeam
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

tag_summary = "Microsoft Exchange Public Folders can be set to allow anonymous connections (set by default). If this is not changed it is possible for
an attacker to gain critical information about the users (such as full email address, phone number, etc) that are present in the Exchange Server.

Additional information:
http://www.securiteam.com/windowsntfocus/5WP091P5FQ.html";

if(description)
{
 script_id(10755);
 script_version("$Revision: 8023 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-07 09:36:26 +0100 (Thu, 07 Dec 2017) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(3301);
 script_cve_id("CVE-2001-0660");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

 name = "Microsoft Exchange Public Folders Information Leak";
 script_name(name);



 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");

 script_copyright("This script is Copyright (C) 2001 SecuriTeam");
 family = "General";
 script_family(family);

 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if ( ! get_port_state(port) ) exit(0);
if ( ! can_host_asp(port:port) ) exit(0);

res = is_cgi_installed_ka(item:"/exchange/root.asp", port:port);
if (res)
{
 Host = "";
 if (get_host_name())
 {
  Host = get_host_name();
 }
 else
 {
  Host = get_host_ip();
 } 

 #display(Host, "\n");
 if (Host)
 {
  first = http_get(item:"/exchange/root.asp?acs=anon", port:port);

  soctcp80 = http_open_socket(port);
  if (soctcp80)
  {
   send(socket:soctcp80, data:first);
   result = http_recv(socket:soctcp80);

   SetCookie = 0;
   #display(result);
   
   if ((egrep(pattern:"^HTTP/[0-9]\.[0-9] 200 .*", string:result)) && ("Set-Cookie: " >< result) && ("top.location='/exchange/logonfrm.asp'" >< result))
   {
    #display("Done First step\n");

    SetCookie = strstr(result, "Set-Cookie: ");
    resultsub = strstr(SetCookie, "; path=/");
    SetCookie = SetCookie - "Set-Cookie: ";
    SetCookie = SetCookie - resultsub;

    #display("Cookie: ", SetCookie, "\n");

    second = string("GET /exchange/logonfrm.asp HTTP/1.1\r\nHost: ", Host, "\r\nCookie: ", SetCookie, "\r\n\r\n");
    

    send(socket:soctcp80, data:second);
    result = http_recv(socket:soctcp80);
    #display(result);

    if ((egrep(pattern:"^HTTP/[0-9]\.[0-9] 302 .*", string:result)) && ("Location: /exchange/root.asp?acs=anon" >< result))
    {
     #display("Done Second step\n");

     third = string("GET /exchange/root.asp?acs=anon HTTP/1.1\r\nHost: ", Host, "\r\nCookie: ", SetCookie, "\r\n\r\n");

     send(socket:soctcp80, data:third);
     result = http_recv(socket:soctcp80);
     #display(result);

     if ((egrep(pattern:"^HTTP/[0-9]\.[0-9] 200 .*", string:result)) && ("/exchange/Navbar/nbAnon.asp" >< result))
     {
      #display("Done Third step\n");

      final = string("POST /exchange/finduser/fumsg.asp HTTP/1.1\r\nHost: ", Host, "\r\nAccept: */*\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 44\r\nCookie: ", SetCookie, "\r\n\r\nDN=a&FN=&LN=&TL=&AN=&CP=&DP=&OF=&CY=&ST=&CO=");

      send(socket:soctcp80, data:final);
      result = http_recv(socket:soctcp80);
      http_close_socket(soctcp80);
      #display(result);
      if ((egrep(pattern:"^HTTP/[0-9]\.[0-9] 200 .*", string:result)) && (("details.asp?obj=" >< result) || ("This query would return" >< result)) )
      {
       security_message(port:port);
      }
     }
    }
   }
  }
 }
}
