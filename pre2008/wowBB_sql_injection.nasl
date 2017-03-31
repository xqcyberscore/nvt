# OpenVAS Vulnerability Test
# $Id: wowBB_sql_injection.nasl 3362 2016-05-20 11:19:10Z antu123 $
# Description: WowBB view_user.php SQL Injection Flaw
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

tag_summary = "The remote web server contains a PHP script that is affected by
a SQL injection flaw.

Description :

The remote host is running WowBB, a web-based forum written in PHP. 

The remote version of this software is vulnerable to SQL injection
attacks through the script 'view_user.php'.  A malicious user can
exploit this issue to manipulate database queries, resulting in
disclosure of sensitive information, attacks against the underlying
database, and the like.";

tag_solution = "Unknown at this time.";

# Ref: Megasky <magasky@hotmail.com>

if(description)
{
  script_id(18221);
  script_version("$Revision: 3362 $");
  script_tag(name:"last_modification", value:"$Date: 2016-05-20 13:19:10 +0200 (Fri, 20 May 2016) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2005-1554");
  script_bugtraq_id(13569);
  script_xref(name:"OSVDB", value:"16543");

  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("WowBB view_user.php SQL Injection Flaw");
 
  script_summary("Checks for SQL injection flaw in wowBB");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("This script is Copyright (C) 2005 David Maciejak");
  script_family("Web application abuses");
  script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
  script_dependencies("http_version.nasl");
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/399637");
  exit(0);
}

# the code!

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

function check(req)
{
  buf = http_get(item:string(req,"/view_user.php?list=1&letter=&sort_by='select"), port:port);
  r = http_keepalive_send_recv(port:port, data:buf, bodyonly:1);
  if( r == NULL )exit(0);
  if ("Invalid SQL query: SELECT" >< r && 'TITLE="WowBB Forum Software' >< r)
  {
 	security_message(port);
	exit(0);
  }
}

port = get_http_port(default:80);
if(!get_port_state(port)) exit(0);
if(!can_host_php(port:port))exit(0);

dirs = make_list("/forum", "/forums", "/board", cgi_dirs());

foreach dir ( dirs ) check(req:dir);
