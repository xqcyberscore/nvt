# OpenVAS Vulnerability Test
# $Id: ping_asp.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: ping.asp
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
# Erik Anderson <eanders@carmichaelsecurity.com>
# Added CAN.  Added link to the Bugtraq message archive
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

tag_summary = "The 'ping.asp' CGI is installed. Some versions
allows a cracker to launch a ping flood against your 
machine or another by entering
'127.0.0.1 -l 65000 -t' in the Address field.";

tag_solution = "remove it.

Reference : http://online.securityfocus.com/archive/82/275088";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.10968");
 script_version("$Revision: 9348 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"qod_type", value:"remote_banner_unreliable");
 
 name = "ping.asp";
 script_name(name);
 



 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright("This script is Copyright (C) 2002 Michel Arboi");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("find_service.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

port = get_http_port(default:80);
if ( ! can_host_asp(port:port) ) exit(0);


if (is_cgi_installed_ka(port:port, item:"ping.asp"))
{
 security_message(port);
 exit(0);
}

if (is_cgi_installed_ka(port:port, item:"/ping.asp"))
{
 security_message(port);
 exit(0);
}
