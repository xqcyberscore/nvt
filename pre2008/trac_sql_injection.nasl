# OpenVAS Vulnerability Test
# $Id: trac_sql_injection.nasl 4619 2016-11-25 06:34:23Z cfi $
# Description: Edgewall Software Trac SQL injection flaw
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
#
# Copyright:
# Copyright (C) 2005 David Maciejak
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

tag_summary = "The remote web server contains a CGI script that is affected by a SQL
injection flaw. 

Description:

The remote host is running Trac, an enhanced wiki and issue tracking
system for software development projects written in python. 

The remote version of this software is prone to a SQL injection flaw
through the ticket query module due to 'group' parameter is not
properly sanitized.";

tag_solution = "Upgrade to Trac version 0.9.1 or later.";

if(description)
{
script_id(20252);
script_version("$Revision: 4619 $");
script_tag(name:"last_modification", value:"$Date: 2016-11-25 07:34:23 +0100 (Fri, 25 Nov 2016) $");
script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
script_cve_id("CVE-2005-3980");
script_bugtraq_id(15676);

script_tag(name:"cvss_base", value:"7.5");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_name("Edgewall Software Trac SQL injection flaw");


script_summary("Checks for SQL injection flaw in Trac");
script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_analysis");
script_copyright("This script is Copyright (C) 2005 David Maciejak");
script_family("Web application abuses");
script_exclude_keys("Settings/disable_cgi_scanning");
script_require_ports("Services/www");
script_dependencies("find_service.nasl", "http_version.nasl");
script_tag(name : "solution" , value : tag_solution);
script_tag(name : "summary" , value : tag_summary);
script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/418294/30/0/threaded");
script_xref(name : "URL" , value : "http://projects.edgewall.com/trac/wiki/ChangeLog");
exit(0);
}

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if ( ! port ) exit(0);
if(!get_port_state(port))exit(0);


# Loop through directories.
dirs = make_list("/trac", cgi_dirs());

foreach dir (dirs)
{
	buf = http_get(item:string(dir,"/query?group=/*"), port:port);
	r = http_keepalive_send_recv(port:port, data:buf, bodyonly:1);
	if( r == NULL )exit(0);
	if("Trac detected an internal error" >< r && egrep(pattern:"<title>Oops - .* - Trac<", string:r))
	{
		security_message(port);
		exit(0);
	}
}
