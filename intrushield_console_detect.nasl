###############################################################################
# OpenVAS Vulnerability Test
# $Id: intrushield_console_detect.nasl 10147 2018-06-11 03:00:29Z ckuersteiner $
#
# McAfee IntruShield management console
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
  script_oid("1.3.6.1.4.1.25623.1.0.15615");
  script_version("$Revision: 10147 $");
  script_tag(name:"last_modification", value:"$Date: 2018-06-11 05:00:29 +0200 (Mon, 11 Jun 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_name("McAfee IntruShield management console");

  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2004 David Maciejak");
  script_family("Service detection");
  # nb: Don't add a dependency to http_version.nasl or gb_get_http_banner.nasl to avoid cyclic dependency to embedded_web_server_detect.nasl
  script_dependencies("find_service.nasl", "httpver.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"The remote host is running the McAfee IntruShield Management Console.

If an attacker can log into it, he will have the ability to modify sensors configuration.");

  script_tag(name:"summary", value:"Configure your firewall to prevent unauthorized hosts from connecting to this
port");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );

url = "/intruvert/jsp/admin/Login.jsp";
res = http_get_cache( item:url, port:port );

if (egrep(pattern:"Copyright (c) 2001 by Intruvert Network Inc\.All rights Reserved\..*<TITLE>IntruShield Login</TITLE>",
          string:res)) {
  log_message( port:port );
  set_kb_item( name:"Services/www/" + port + "/embedded", value:TRUE );
}

exit( 0 );
