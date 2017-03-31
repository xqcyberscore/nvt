###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_openvas_administrator_detect.nasl 4034 2016-09-12 12:12:26Z cfi $
#
# OpenVAS Administrator Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_oid("1.3.6.1.4.1.25623.1.0.103826");
  script_version ("$Revision: 4034 $");
  script_tag(name:"last_modification", value:"$Date: 2016-09-12 14:12:26 +0200 (Mon, 12 Sep 2016) $");
  script_tag(name:"creation_date", value:"2013-11-08 12:28:10 +0100 (Fri, 08 Nov 2013)");
  script_name("OpenVAS Administrator Detection");
  script_summary("Checks for the presence of OpenVAS Administrator");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/unknown", 9393);

  tag_summary = "The script sends a connection request to the server and attempts to
  determine if it is a OpenVAS Administrator";

  script_tag(name : "summary" , value : tag_summary);

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");

port = get_unknown_port( default:9393 );

soc = open_sock_tcp(port);
if(!soc)exit(0);

send(socket:soc, data:'<foo/>\r\n');
ret = recv(socket:soc, length:256);

close(soc);

if("oap_response" >< ret && "GET_VERSION" >< ret) {

  set_kb_item(name:"openvas_administrator/installed",value:TRUE);
  cpe = 'cpe:/a:openvas:openvas_administrator';

  register_product(cpe:cpe, location:port + '/tcp', port:port);

  log_message(data:'OpenVAS Administrator was detected on this port.\nCPE: ' + cpe + '\n', port:port);
  exit(0);

}

exit(0);

