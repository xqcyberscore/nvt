# OpenVAS Vulnerability Test
# $Id: tinyweb.nasl 8023 2017-12-07 08:36:26Z teissa $
# Description: TinyWeb 1.9
#
# Authors:
# Matt North
#
# Copyright:
# Copyright (C) 2003 Matt North
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

tag_summary = "The remote host is running TinyWeb version 1.9 or older.

A remote user can issue an HTTP GET request for /cgi-bin/.%00./dddd.html 
and cause the server consume large amounts of CPU time (88%-92%).";

tag_solution = "contact vendor http://www.ritlabs.com";

if(description)
{
 script_id(11894);
 script_version("$Revision: 8023 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-07 09:36:26 +0100 (Thu, 07 Dec 2017) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"7.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_cve_id("CVE-2003-1510");
 script_bugtraq_id(8810);
 
 name = "TinyWeb 1.9";

 script_name(name);
 

 
 
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
 
 
 script_copyright("This script is Copyright (C) 2003 Matt North");
 script_family("Web application abuses");
 script_require_ports("Services/www", 80);
 script_dependencies("gb_get_http_banner.nasl");
 script_mandatory_keys("TinyWeb/banner");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");

port = get_http_port(default:80);


if(get_port_state(port)) {
        ban = get_http_banner(port: port);
        if(!ban) exit(0);
        if(egrep(pattern:"^Server:.*TinyWeb/(0\..*|1\.[0-9]([^0-9]|$))",
		 string:ban))security_message(port);
}
