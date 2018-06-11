###############################################################################
# OpenVAS Vulnerability Test
# $Id: interspect_detect.nasl 10147 2018-06-11 03:00:29Z ckuersteiner $
#
# CheckPoint InterSpect
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
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.15614");
  script_version("$Revision: 10147 $");
  script_tag(name:"last_modification", value:"$Date: 2018-06-11 05:00:29 +0200 (Mon, 11 Jun 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");

  script_name("CheckPoint InterSpect");

  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2004 David Maciejak");
  script_family("Service detection");
  # nb: Don't add a dependency to http_version.nasl to or gb_get_http_banner.nasl avoid cyclic dependency to embedded_web_server_detect.nasl
  script_dependencies("find_service.nasl", "httpver.nasl");
  script_require_ports("Services/www", 80, 3128);
  script_exclude_keys("Settings/disable_cgi_scanning");

  tag_summary = "The remote host seems to be running CheckPoint InterSpect,
  an internet security gateway.

  The OpenVAS host is liked to have been put in quarantine,
  its activity will be dropped for 30 minutes by default.";

  script_tag(name:"summary", value:"The remote host seems to be running CheckPoint InterSpect, an internet
security gateway.

The scanner host is liked to have been put in quarantine, its activity will be dropped for 30 minutes by default.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );

r = http_get_cache( item:"/", port:port );
if( r == NULL ) exit( 0 );

if( egrep( pattern:"<TITLE>Check Point InterSpect - Quarantine</TITLE>.*Check Point InterSpect", string:r ) ) {
  log_message( port:port );
  set_kb_item( name:"Services/www/" + port + "/embedded", value:TRUE );
}

exit( 0 );
