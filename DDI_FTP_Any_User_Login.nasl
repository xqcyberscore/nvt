###################################################################
# OpenVAS Vulnerability Test
# $Id: DDI_FTP_Any_User_Login.nasl 4718 2016-12-08 13:32:01Z cfi $
#
# FTP Service Allows Any Username
#
# Authors:
# H D Moore
#
# Copyright:
# Copyright (C) 2002 Digital Defense Inc.
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
###################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10990");
  script_version("$Revision: 4718 $");
  script_tag(name:"last_modification", value:"$Date: 2016-12-08 14:32:01 +0100 (Thu, 08 Dec 2016) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("FTP Service Allows Any Username");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2002 Digital Defense Inc.");
  script_family("FTP");
  script_dependencies("find_service_3digits.nasl", "ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);

  tag_summary = "The FTP service can be accessed using any username and password.
  Many other plugins may trigger falsely because of this, so 
  OpenVAS enable some countermeasures.

  ** If you find a useless warning on this port, please inform
  ** the OpenVAS team so that we fix the plugins.";

  tag_solution = "None";

  script_tag(name:"solution", value:tag_solution);
  script_tag(name:"summary", value:tag_summary);

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include('global_settings.inc');
include('ftp_func.inc');
include('misc_func.inc');

port = get_ftp_port( default:21 );

n_cnx = 0; n_log = 0;

banner = get_ftp_banner( port:port );
if( ! banner ) exit( 0 );

for (i = 0; i < 4; i ++)
{
 soc = open_sock_tcp(port);
 if(soc)
 {
   n_cnx ++;
   u = rand_str(); p = rand_str();
   if (ftp_authenticate(socket:soc, user: u, pass: p))
     n_log ++;
   else
     exit(0);
   ftp_close(socket: soc);
 }
 else
  sleep(1);
}

debug_print('n_log=', n_log, '/ n_cnx=', n_cnx, '\n');

if (n_cnx > 1 && n_log >= n_cnx - 1)	# >= n_cnx ?
{
 set_kb_item(name:"ftp/" + port + "/AnyUser", value:TRUE);
 if (report_verbosity > 1) log_message(port:port);
} 
