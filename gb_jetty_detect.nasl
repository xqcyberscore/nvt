###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_jetty_detect.nasl 6063 2017-05-03 09:03:05Z teissa $
#
# Jetty Version Detection
#
# Authors:
# Nikita MR <rnikita@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.800953");
  script_version("$Revision: 6063 $");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-05-03 11:03:05 +0200 (Wed, 03 May 2017) $");
  script_tag(name:"creation_date", value:"2009-10-20 14:26:56 +0200 (Tue, 20 Oct 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Jetty Version Detection");
  script_tag(name: "summary" , value: "Detection of Jetty WebServer.

  The script sends a connection request to the server and attempts to
  extract the version number from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("Jetty/banner");
  script_require_ports("Services/www", 8080);
  exit(0);
}


include("cpe.inc");
include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

## Default port
jettyPort = get_http_port(default:8080);
if(!jettyPort){
  jettyPort = 8080;
}

## Check the port state
if(!get_port_state(jettyPort)){
  exit(0);
}

## Get the banner
banner = get_http_banner(port:jettyPort);

## confirm the server
if("Server: Jetty" >< banner)
{
  jettyVer = eregmatch(pattern:"Jetty.([0-9.]+)([a-zA-Z]+[0-9]+)?", string:banner);

  if(jettyVer[1] != NULL)
  {
    if(jettyVer[2] != NULL)
    {
      if(jettyVer[2] =~ "^v"){
        jettyVer[2] = jettyVer[2] -"v";
      }

      if(jettyVer[1] =~ "\.$" ){
       jettyVer = jettyVer[1] +  jettyVer[2];
      }
      else {
        jettyVer = jettyVer[1] + "." + jettyVer[2];
     }
    }

  else{
      jettyVer = jettyVer[1];
  }

  set_kb_item(name:"www/" + jettyPort + "/Jetty", value:jettyVer);
  set_kb_item(name:"Jetty/installed", value:TRUE);

   cpe = build_cpe(value:jettyVer, exp:"^([0-9.]+)", base:"cpe:/a:mortbay:jetty:");
   if(!cpe)
     cpe = 'cpe:/a:mortbay:jetty';

   register_product(cpe:cpe, location:jettyPort);
   log_message(data: build_detection_report(app:"Jetty WebServer",
                                            version:jettyVer,
                                            install:"/",
                                            cpe:cpe,
                                            concluded:jettyVer),
                                            port:jettyPort);


 }
}
