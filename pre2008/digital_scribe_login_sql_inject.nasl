# OpenVAS Vulnerability Test
# $Id: digital_scribe_login_sql_inject.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: Digital Scribe login.php SQL Injection flaw
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

tag_summary = "The remote web server contains a PHP script which is vulnerable to a SQL
injection. 

Description : 

The remote web server hosts Digital Scribe, a student-teacher set of
scripts written in PHP.

The version of Digital Scribe installed on the remote host is prone to
SQL injection attacks through the 'login.php' script.  A malicious
user may be able to exploit this issue to manipulate database queries
to, say, bypass authentication.";

tag_solution = "Unknown at this time.";

# Ref: retrogod at aliceposta.it

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.19770");
  script_version("$Revision: 9348 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
  script_cve_id("CVE-2005-2987");
  script_bugtraq_id(14843);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Digital Scribe login.php SQL Injection flaw");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_active");
  script_copyright("This script is Copyright (C) 2005 David Maciejak");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_xref(name : "URL" , value : "http://retrogod.altervista.org/dscribe14.html");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!can_host_php(port:port))exit(0);

foreach dir( make_list_unique( "/DigitalScribe", "/scribe", cgi_dirs( port:port ) )) {

  if( dir == "/" ) dir = "";
  r = http_get_cache(item:string(dir,"/login.php"), port:port);
  if( r == NULL ) continue;

  if (("<TITLE>Login Page</TITLE>" >< r) && (egrep(pattern:"www\.digital-scribe\.org>Digital Scribe v\.1\.[0-4]$</A>", string:r))) {
    security_message( port:port );
    exit( 0 );
  }
}

exit( 99 );