###############################################################################
# OpenVAS Vulnerability Test
# $Id: asp_inline_sql_injection.nasl 7275 2017-09-26 11:46:31Z cfischer $
#
# ASP Inline Corporate Calendar SQL injection
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

# ASP Inline Corporate Calendar SQL injection
# "Zinho" <zinho@hackerscenter.com>
# 2005-05-03 18:50

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.18187");
  script_version("$Revision: 7275 $");
  script_tag(name:"last_modification", value:"$Date: 2017-09-26 13:46:31 +0200 (Tue, 26 Sep 2017) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_bugtraq_id(13487, 13485);
  script_cve_id("CVE-2005-1481");
  script_name("ASP Inline Corporate Calendar SQL injection");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2005 Noam Rathaus");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Disable this script");

  script_tag(name:"summary", value:"The remote host is running Corporate Calendar, an ASP script to manage a 
  calendar shared by users. It has been downloaded by thousands people, and 
  it is considered one of the most successful ASP script at hotscripts.com.

  Multiple SQL injections affect ASP Inline Corporate Calendar.");

  script_tag(name:"qod_type", value:"remote_app");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );
if( ! can_host_asp( port:port ) ) exit( 0 );

foreach dir (make_list_unique("/", "/calendar", cgi_dirs(port:port))) {

  if( dir == "/" ) dir = "";

  url = dir + "/details.asp?Event_ID='";
  req = http_get( item:url, port:port );
  r = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );
  if( isnull( r ) ) continue;

  if( "Syntax error in string in query expression 'Event_ID LIKE" >< r ) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );