###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_memcached_detect.nasl 8695 2018-02-06 16:42:37Z cfischer $
#
# Memcached Version Detection
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
  script_oid("1.3.6.1.4.1.25623.1.0.800714");
  script_version("$Revision: 8695 $");
  script_tag(name:"last_modification", value:"$Date: 2018-02-06 17:42:37 +0100 (Tue, 06 Feb 2018) $");
  script_tag(name:"creation_date", value:"2009-05-18 09:37:31 +0200 (Mon, 18 May 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Memcached Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/unknown", 11211);

  script_tag(name:"summary", value:"Detection of Memcached.

  The script sends a connection request to the server and attempts to
  extract the version number from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("misc_func.inc");

port = get_unknown_port( default:11211 );

appsock = "";
response = "";
version = "";

data = string("version \r\n");
appsock = open_sock_tcp(port);
if(!appsock){
  exit(0);
}

send(socket:appsock, data:data);
response = recv(socket:appsock, length:64);

close(appsock);

if(!response){
  exit(0);
}

if( response !~ '^VERSION [0-9.\r\n]+$' ) exit( 0 );

version = eregmatch(pattern:"VERSION ([0-9.]+)", string:response);
if(version[1] != NULL)
{
  set_kb_item(name:"MemCached/installed", value:TRUE);
  set_kb_item(name:"MemCached/Ver", value:version[1]);

  ## build cpe and store it as host_detail
  cpe = build_cpe(value:version[1], exp:"^([0-9.]+)", base:"cpe:/a:memcachedb:memcached:");
  if(isnull(cpe))
    cpe = 'cpe:/a:memcachedb:memcached';

  register_product(cpe:cpe, location:port + "/TCP", port:port);
  register_service( port:port, proto:'memcached' );

  log_message(data: build_detection_report(app:"MemCached", version:version[1], install:port + "/tcp",
            cpe:cpe, concluded:version[0]), port:port);
  exit(0);

}

exit( 0 );
