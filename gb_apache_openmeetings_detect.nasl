###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_openmeetings_detect.nasl 5351 2017-02-20 08:03:12Z mwiegand $
#
# Apache OpenMeetings Detection
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.808657");
  script_version("$Revision: 5351 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-02-20 09:03:12 +0100 (Mon, 20 Feb 2017) $");
  script_tag(name:"creation_date", value:"2016-08-23 14:59:46 +0530 (Tue, 23 Aug 2016)");
  script_name("Apache OpenMeetings Detection");
  script_tag(name:"summary", value:"Detection of Installed version of
  Apache OpenMeetings application.

  This script sends HTTP GET request and try to ensure the presence of Apache
  OpenMeetings from the response.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_summary("Check for the presence of Apache OpenMeetings application");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 5080);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

include("cpe.inc");
include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

## Variable Initialization
dir = "";
openPort = 0;
rcvRes = "";

##Get HTTP Port
if(!openPort = get_http_port(default:5080)){
  exit(0);
}

##Iterate over possible paths
foreach dir(make_list_unique("/", "/openmeetings", "/apache/openmeetings",  cgi_dirs(port:openPort))) 
{
  install = dir;
  if(dir == "/") dir = "";

  ## Send and receive response
  sndReq = http_get(item: dir + "/signin", port:openPort);
  rcvRes = http_send_recv(port:openPort, data:sndReq);

  ##Confirm application
  if('>OpenMeetings<' >< rcvRes && '>Username or mail address<' >< rcvRes && 
     '>Password<' >< rcvRes ) 
  {
    version = "unknown";

    ## Set the KB value
    set_kb_item(name:"Apache/Openmeetings/Installed", value:TRUE);

    ## build cpe and store it as host_detail
    cpe = "cpe:/a:apache:openmeetings:";

    register_product(cpe:cpe, location:install, port:openPort);

    log_message( data:build_detection_report( app:"Apache Openmeetings",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              concluded:version),
                                              port:openPort);
  }
}
exit(0);
