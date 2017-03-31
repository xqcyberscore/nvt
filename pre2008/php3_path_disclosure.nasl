# OpenVAS Vulnerability Test
# $Id: php3_path_disclosure.nasl 3376 2016-05-24 07:53:16Z antu123 $
# Description: PHP3 Physical Path Disclosure Vulnerability
#
# Authors:
# Matt Moore <matt.moore@westpoint.ltd.uk>
# www.westpoint.ltd.uk
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
# Ian Koenig <ian@carmichaelsecurity.com>
# Added link to the Bugtraq message archive
#
# Copyright:
# Copyright (C) 2001 Matt Moore
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

tag_summary = "PHP3 will reveal the physical path of the 
webroot when asked for a non-existent PHP3 file
if it is incorrectly configured. Although printing errors 
to the output is useful for debugging applications, this 
feature should not be enabled on production servers.";

tag_solution = "In the PHP configuration file change display_errors to 'Off':
   display_errors  =   Off

Reference : http://online.securityfocus.com/archive/1/65078
Reference : http://online.securityfocus.com/archive/101/184240";


if(description)
{
 script_id(10670);
 script_version("$Revision: 3376 $");
 script_tag(name:"last_modification", value:"$Date: 2016-05-24 09:53:16 +0200 (Tue, 24 May 2016) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 name = "PHP3 Physical Path Disclosure Vulnerability";
 script_name(name);
 

 summary = "Tests for PHP3 Physical Path Disclosure Vulnerability";
 
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_analysis");
 
 script_copyright("This script is Copyright (C) 2001 Matt Moore");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

# Actual check starts here...
# Check makes a request for non-existent php3 file...

include("http_func.inc");

port = get_http_port(default:80);

if(get_port_state(port))
{ 
 if ( ! can_host_php(port:port) ) exit(0);
 req = http_get(item:"/nosuchfile-10303-10310.php3", port:port);
 soc = http_open_socket(port);
 if(soc)
 {
 send(socket:soc, data:req);
 r = http_recv(socket:soc);
 http_close_socket(soc);
 if("Unable to open" >< r)	
 	security_message(port);

 }
}
