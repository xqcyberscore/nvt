# OpenVAS Vulnerability Test
# $Id: PC_anywhere_tcp.nasl 8086 2017-12-12 13:08:13Z teissa $
# Description: pcAnywhere TCP
#
# Authors:
# Georges Dagousset <georges.dagousset@alert4web.com>
# Changes by Tenable Network Security : cleanup + better detection
#
# Copyright:
# Copyright (C) 2001 Alert4Web.com
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
#

tag_summary = "pcAnywhere is running on this port";

tag_solution = "Disable this service if you do not use it.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10794");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 8086 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-12 14:08:13 +0100 (Tue, 12 Dec 2017) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  name = "pcAnywhere TCP";
  script_name(name);
  summary = "Checks for the presence pcAnywhere";
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("This script is Copyright (C) 2001 Alert4Web.com");
  family = "Windows";
  script_family(family);
  script_dependencies("os_detection.nasl", "find_service.nasl");
  script_require_ports("Services/unknown", 5631);
  script_mandatory_keys("Host/runs_windows");

  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);

  exit(0);
}

include("misc_func.inc");
include("global_settings.inc");
include("host_details.inc");

port = get_unknown_port( default:5631 );

soc = open_sock_tcp(port);
if(soc)
{
  send(socket:soc, data:raw_string(0,0,0,0));
  r = recv(socket:soc, length:36);
  if (r && ("Please press <" >< r))
  {
     register_service(port:port, proto:"pcanywheredata");
     log_message(port);
     exit(0);
  }
  close(soc);
}

exit(0);