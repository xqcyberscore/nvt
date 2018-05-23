###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_sun_java_app_serv_detect.nasl 9927 2018-05-23 04:13:59Z ckuersteiner $
#
# Sun Java System Application Server Version Detection
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Updated By Veerendra G <veerendragg@secpod.com>
# date update: 2010/02/05
# Added logic to detect Sun Java System Application Server Version from
# Response headers
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.900200");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 9927 $");
  script_tag(name:"last_modification", value:"$Date: 2018-05-23 06:13:59 +0200 (Wed, 23 May 2018) $");
  script_tag(name:"creation_date", value:"2009-02-06 06:53:35 +0100 (Fri, 06 Feb 2009)");
  script_tag(name:"cvss_base", value:"0.0");

  script_name("Sun Java System Application Server Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Service detection");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80, 8080);

  script_tag(name: "summary" , value: "This script detects the installed version of Application Server and sets
the version in KB.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

port = get_http_port(default:8080);

rcvRes = http_get_cache(item:"/", port:port);
if (rcvRes == NULL)
  exit(0);

## Sun Java System Application Server Formerly known as
## Sun ONE Application Server and now it is known as
## Sun GlassFish Enterprise Server
## http://www.sun.com/software/products/appsrvr/index.jsp

## Get Version from Response headers Sample Headers,
## Server: Sun-ONE-Application-Server/7.0.0_11
## Server: Sun-Java-System-Application-Server/7 2004Q2UR6
## Sun Java System Application Server Platform Edition 9.0_01

## Grep for Sun Java System Application Server Version from Response Headers.
appservVer = eregmatch(pattern:"Server: Sun[- a-zA-Z]+Application[- ]Server/?([a-zA-Z0-9._ ]+)", string: rcvRes);

if (appservVer[1] != NULL) {
  appservVer = appservVer[1] - " Platform Edition ";
  appservVer = chomp(appservVer);
  set_kb_item(name:"sun_java_appserver/installed", value: TRUE);

  ## build cpe and store it as host_detail
  register_and_report_cpe(app:"Sun Java Application Server", ver:appservVer,
                          base:"cpe:/a:sun:java_system_application_server:",
                          expr:"^([0-9.]+)", insloc:"/");
  exit(0);
}

if (egrep(pattern:"Sun Java System Application Server .*", string:rcvRes)) {
  # Grep the Java Application Server Version from response
  appservVer = eregmatch(pattern:"Platform Edition ([0-9.]+)", string:rcvRes);
  if(appservVer[1] != NULL){
    set_kb_item(name:"sun_java_appserver/installed", value: TRUE);

    ## build cpe and store it as host_detail
    register_and_report_cpe(app:"Sun Java Application Server", ver:appservVer[1], 
                          base:"cpe:/a:sun:java_system_application_server:", 
                          expr:"^([0-9.]+)", insloc:"/");
    exit(0);
  }
}

exit(0);
