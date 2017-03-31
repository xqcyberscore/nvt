###############################################################################
# OpenVAS Vulnerability Test
# $Id: nntpserver_detect.nasl 4682 2016-12-06 08:14:23Z cfi $
#
# News Server type and version
#
# Authors:
# Noam Rathaus <noamr@securiteam.com>
#
# Copyright:
# Copyright (C) 1999 SecuriTeam
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
  script_oid("1.3.6.1.4.1.25623.1.0.10159");
  script_version("$Revision: 4682 $");
  script_tag(name:"last_modification", value:"$Date: 2016-12-06 09:14:23 +0100 (Tue, 06 Dec 2016) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("News Server type and version");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 1999 SecuriTeam");
  script_family("Service detection");
  script_dependencies("find_service_3digits.nasl");
  script_require_ports("Services/nntp", 119);

  tag_summary = "This detects the News Server's type and version by connecting to the server
  and processing the buffer received.
  This information gives potential attackers additional information about the
  system they are attacking. Versions and Types should be omitted
  where possible.";

  tag_solution = "Change the login banner to something generic";

  script_tag(name:"solution", value:tag_solution);
  script_tag(name:"summary", value:tag_summary);

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("misc_func.inc");
include("nntp_func.inc");

port = get_nntp_port( default:119 );

soc = open_sock_tcp( port );
if( ! soc ) exit( 0 );

res = recv_line( socket:soc, length:1024 );
if( ! res || tolower( res ) !~ "^200.*nntp" ) exit( 0 );

res = string( "Remote NNTP server version : ", res );

set_kb_item( name:"nntp/installed", value:TRUE );
register_service( port:port, ipproto:"tcp", proto:"nntp" );
log_message( port:port, data:res );
close(soc);

exit( 0 );
