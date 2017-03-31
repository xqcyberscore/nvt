# OpenVAS Vulnerability Test
# $Id: bblog_sql_inject.nasl 3398 2016-05-30 07:58:00Z antu123 $
# Description: bBlog SQL injection flaw
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
# based on work from (C) Tenable Network Security
#
# Copyright:
# Copyright (C) 2004 David Maciejak
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

tag_summary = "The remote server runs a version of bBlog, a blogging system written in PHP 
and released under the GPL, which is as old as or older than version 0.7.4.

The remote version of this software is affected by a SQL injection
attacks in the script 'rss.php'. This issue is due to a failure 
of the application to properly sanitize user-supplied input.

An attacker may use these flaws to execute arbitrary PHP code on this
host or to take the control of the remote database.";

tag_solution = "Upgrade to version 0.7.4 or newer.";

#  Ref: James McGlinn <james servers co nz>

if(description)
{
 script_id(15466);
 script_version("$Revision: 3398 $");
 script_tag(name:"last_modification", value:"$Date: 2016-05-30 09:58:00 +0200 (Mon, 30 May 2016) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_cve_id("CVE-2004-1570");
 script_bugtraq_id(11303);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 
 name = "bBlog SQL injection flaw";
 script_name(name);
 

 summary = "Check bBlog version";
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  
 script_copyright("This script is Copyright (C) 2004 David Maciejak");
		
 family = "Web application abuses";
 script_family(family);
 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
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
if(!port) exit(0);
if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);


foreach dir (make_list(cgi_dirs(),  "/bblog"))
{
 buf = http_get(item:string(dir,"/index.php"), port:port);
 r = http_keepalive_send_recv(port:port, data:buf, bodyonly:1);
 if( r == NULL )exit(0);
 if(egrep(pattern:"www\.bBlog\.com target=.*bBlog 0\.([0-6]\.|7\.[0-3][^0-9]).*&copy; 2003 ", string:r)) security_message(port);
}
