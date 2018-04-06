# OpenVAS Vulnerability Test
# $Id: wowBB_flaws.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: WowBB <= 1.61 multiple flaws
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
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
# Ref: Positive Technologies - www.maxpatrol.com

tag_summary = "The remote web server contains a PHP application that is prone to
multiple flaws. 

Description :

The remote host is running WowBB, a web-based forum written in PHP. 

According to its version, the remote installation of WowBB is 1.61 or
older.  Such versions are vulnerable to cross-site scripting and SQL
injection attacks.  A malicious user can steal users' cookies,
including authentication cookies, and manipulate SQL queries.";

tag_solution = "Unknown at this time.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.15557");
  script_version("$Revision: 9348 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2004-2180", "CVE-2004-2181");
  script_bugtraq_id(11429);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("WowBB <= 1.61 multiple flaws");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("This script is Copyright (C) 2004 David Maciejak");
  script_family("Web application abuses");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_xref(name : "URL" , value : "http://www.maxpatrol.com/advdetails.asp?id=7");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!can_host_php(port:port))exit(0);

foreach dir( make_list_unique( "/forum", "/forums", "/board", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  r = http_get_cache(item:string(dir, "/index.php"), port:port);
  if( r == NULL ) continue;

  if(egrep(pattern:"WowBB Forums</TITLE>.*TITLE=.WowBB Forum Software.*>WowBB (0\..*|1\.([0-5][0-9]|60|61))</A>", string:r)) {
    security_message(port);
    exit(0);
  }
}

exit( 99 );