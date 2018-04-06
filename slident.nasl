###############################################################################
# OpenVAS Vulnerability Test
# $Id: slident.nasl 9347 2018-04-06 06:58:53Z cfischer $
#
# Detect slident and or fake identd
#
# Authors:
# Michel Arboi <mikhail@nessus.org>
#
# Copyright:
# Copyright (C) 2005 Michel Arboi
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.18373");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 9347 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 08:58:53 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Detect slident and or fake identd");
  script_family("General");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("This script is Copyright (C) 2005 Michel Arboi");
  script_require_ports("Services/auth", 113);
  script_dependencies("find_service1.nasl", "secpod_open_tcp_ports.nasl");
  script_mandatory_keys("TCP/PORTS");

  tag_summary = "The remote ident server returns random token instead of 
  leaking real user IDs. This is a good thing.";

  script_tag(name:"summary", value:tag_summary);

  exit(0);
}

include('global_settings.inc');
include('misc_func.inc');

iport = get_kb_item( "Services/auth" );
if( ! iport ) iport = 113;
if( ! get_port_state( iport ) ) exit(0);

port = get_host_open_tcp_port();
if( ! port ) port = iport;

debug_print(level: 2, 'port=', port, ', iport=', iport);

j = 0;
for (i = 0; i < 3; i ++)	# Try more than twice, just in case
{
 soc = open_sock_tcp(port);
 if (soc)
 {
  req = strcat(port, ',', get_source_port(soc), '\r\n');
  isoc = open_sock_tcp(iport);
  if (isoc)
  {
   send(socket: isoc, data: req);
   id = recv_line(socket: isoc, length: 1024);
   if (id)
   {
    ids = split(id, sep: ':');
    if ("USERID" >< ids[1])
    {
     got_id[j ++] = ids[3];
     debug_print('ID=', ids[3], '\n');
    }
   }
   close(isoc);
  }
  close(soc);
 }
}

slident = 0;
if (j == 1)
{
 # This is slidentd
 if (got_id[0] =~ '^[a-f0-9]{32}$')
 {
  debug_print('slident detected on port ', iport, '\n');
  slident = 1;
 }
}
else
 for (i = 1; i < j; i ++)
  if (got_id[i-1] != got_id[i])
  {
   slident = 1;	# Maybe not slident, but a fake ident anyway
   debug_print('Ident server on port ', iport, ' returns random tokens: ',
	chomp(got_id[i-1]), ' != ', chomp(got_id[i]), '\n');
   break;
  }

if (slident)
{
  if ( report_verbosity > 1 ) log_message(port: iport);
  log_print('Ident server on port ', iport, ' is not usable\n');
  set_kb_item(name: 'fake_identd/'+iport, value: TRUE);
}

