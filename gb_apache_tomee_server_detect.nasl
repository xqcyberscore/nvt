###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_tomee_server_detect.nasl 6588 2017-07-07 08:21:40Z santu $
#
# Apache TomEE Server Version Detection
#
# Authors:
# Rinu Kuriaksoe <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.810964");
  script_version("$Revision: 6588 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-07-07 10:21:40 +0200 (Fri, 07 Jul 2017) $");
  script_tag(name:"creation_date", value:"2017-06-28 16:34:52 +0530 (Wed, 28 Jun 2017)");
  script_name("Apache TomEE Server Version Detection");
  script_tag(name:"summary", value:"Detection of installed version
  of Apache TomEE server.

  This script sends HTTP GET request and try to get the version from the
  response.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

## Variable initialization
tikaPort = "";
req = "";
rcvRes = "";
version = "";
ver = "";

## get port
tomeePort = get_http_port(default:8080);

## send request and receive response
rcvRes = http_get_cache(item: "/", port: tomeePort);

## Confirm the application>
if("Server: Apache TomEE" >< rcvRes && rcvRes =~ "<title>Apache Tomcat \(TomEE\).*</title>") 
{
  ## Grep for the version
  ver = eregmatch(pattern:'<title>Apache Tomcat \\(TomEE\\)/(.*) \\(([ 0-9A-Za-z.-]+)\\)</title>', string:rcvRes);
  if( ver[2] )
  {
    ## some times versions comes with '-' and space
    version = ereg_replace( string:ver[2], pattern: "-| ", replace: "." );
    set_kb_item(name:"Apache/TomEE/Server/ver", value:version);
  } else {
    version = "unknown";
  }

  ## Set the KB value
  set_kb_item(name:"Apache/TomEE/Server/Installed", value:TRUE);

  ## build cpe and store it as host_detail
  cpe = build_cpe(value:version, exp:"^([ 0-9A-Za-z.-]+)", base:"cpe:/a:apache:tomee:");
  if( ! cpe )
    cpe = "cpe:/a:apache:tomee";


  register_product(cpe:cpe, location:"/", port:tomeePort);

  log_message(data:build_detection_report(app:"Apache TomEE Server",
                                          version:version,
                                          install:"/",
                                          cpe:cpe,
                                          concluded:version),
                                          port:tomeePort);
}
exit(0);
