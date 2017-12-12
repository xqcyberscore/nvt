###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_serimux_ssh_console_switch_detect.nasl 8078 2017-12-11 14:28:55Z cfischer $
#
# Serimux SSH Console Switch Detection
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.807894");
  script_version("$Revision: 8078 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-12-11 15:28:55 +0100 (Mon, 11 Dec 2017) $");
  script_tag(name:"creation_date", value:"2016-10-05 16:18:47 +0530 (Wed, 05 Oct 2016)");
  script_name("Serimux SSH Console Switch Detection");

  script_tag(name:"summary", value:"Detection of installed version of
  Serimux SSH Console Switch.

  This script sends HTTP GET request and try to ensure the presence of
  Serimux SSH Console Switch.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

serPort = get_http_port( default:80 );
if( ! can_host_asp( port:serPort ) ) exit( 0 );

foreach dir(make_list_unique("/", "/cgi_dir", cgi_dirs(port:serPort))) {

  install = dir;
  if(dir == "/") dir = "";

  ## Send and receive response
  sndReq = http_get(item: dir + "/nti/login.asp", port:serPort);
  rcvRes = http_send_recv(port:serPort, data:sndReq);

  ##Confirm application
  if(">SERIMUX-S-x Console Switch" >< rcvRes && ">Welcome, please log in" >< rcvRes)
  {
    version = "unknown";

    ## Set the KB value
    set_kb_item(name:"Serimux/Console/Switch/Installed", value:TRUE);

    ## Created new cpe
    ## build cpe and store it as host_detail
    cpe = "cpe:/a:serimux:serimux_console_switch";

    register_product(cpe:cpe, location:install, port:serPort);

    log_message(data:build_detection_report( app:"Serimux SSH Console Switch",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              concluded:version),
                                              port:serPort);
    exit(0);
  }
}
exit(0);
