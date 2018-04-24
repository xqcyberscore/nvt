###############################################################################
# OpenVAS Vulnerability Test
# $Id: telnetserver_detect_type_nd_version.nasl 9580 2018-04-24 08:44:20Z jschulte $
#
# Report Telnet Banner
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
  script_oid("1.3.6.1.4.1.25623.1.0.10281");
  script_version("$Revision: 9580 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-24 10:44:20 +0200 (Tue, 24 Apr 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Report Telnet Banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 1999 SecuriTeam");
  script_family("Service detection");
  script_dependencies("telnet.nasl");
  script_require_ports("Services/telnet", 23);
  script_mandatory_keys("telnet/banner/available");

  script_tag(name:"summary", value:"This scripts reports the received banner of a Telnet Server.");
  script_tag(name:"impact", value:"This information gives potential attackers additional information about the
  system they are attacking. Versions and Types should be omitted
  where possible.");
  script_tag(name:"solution", value:"Change the login banner to something generic.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("telnet_func.inc");

port = get_telnet_port( default:23 );

banner = get_telnet_banner( port:port );

if( strlen( banner ) ) {
  data = 'Remote telnet banner :\n';
  if( banner ) data += banner;
  log_message( port:port, data:data );
}

exit( 0 );