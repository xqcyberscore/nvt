###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_rave_detect.nasl 4624 2016-11-25 07:00:59Z cfi $
#
# Apache Rave Version Detection
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
  script_oid("1.3.6.1.4.1.25623.1.0.803179");
  script_version("$Revision: 4624 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2016-11-25 08:00:59 +0100 (Fri, 25 Nov 2016) $");
  script_tag(name:"creation_date", value:"2013-03-14 16:52:17 +0530 (Thu, 14 Mar 2013)");
  script_name("Apache Rave Version Detection");

 script_summary("Checks for the presence of Apache Rave");
 script_category(ACT_GATHER_INFO);
 script_family("Product detection");
 script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
 script_require_ports("Services/www", 8080);
  script_dependencies("find_service.nasl", "http_version.nasl");

 script_tag(name : "summary" , value : "Detection of Apache Rave.

 The script sends a connection request to the server and attempts to
 extract the version number from the reply.");

 script_tag(name:"qod_type", value:"remote_banner");
 exit(0);
}


include("cpe.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");
include("host_details.inc");

## Variables Initialization
cpe = "";
url = "";
req = "";
buf = "";
vers = "";
dirs = "";
port = "";
version = "";
install = "";

## Get the default port
port = get_http_port(default:8080);
if(!port){
  exit(0);
}

## Check the port status
if(!get_port_state(port)){
  exit(0);
}

## List and and iterate over the possible paths
foreach dir (make_list_unique("/", "/rave", "/portal", "/social", cgi_dirs()))
{

  install = dir;
  if (dir == "/")
    dir = "";

  url = string(dir, "/login");
  req = http_get(item:url, port:port);
  buf = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if( buf == NULL ){
    continue;
  }

  ## Confirm the application
  if(">RAVE<" >< buf && ">Apache Rave" >< buf)
  {

    vers = string("unknown");

    ### try to get version
    version = eregmatch(string:buf, pattern:'>Apache Rave ([0-9.]+)',icase:TRUE);
    if(!isnull(version[1])) {
      vers=chomp(version[1]);
    }

    ## set the kb
    set_kb_item(name: string("www/", port, "/ApacheRave"),
                value: string(vers," under ",install));
    set_kb_item(name:"ApacheRave/installed", value:TRUE);

    ## build cpe
    cpe = build_cpe(value:vers, exp:"^([0-9.]+)", base:"cpe:/a:apache:rave:");
    if(isnull(cpe))
      cpe = 'cpe:/a:apache:rave';

    ## register the product
    register_product(cpe:cpe, location:install, port:port);
    log_message(data: build_detection_report(app:"Apache Rave",
                                             version:vers,
                                             install:install,
                                             cpe:cpe,
                                             concluded:version[0]),
                                             port:port);
  }
}

exit(0);