###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_opac_kpwinsql_detect.nasl 5900 2017-04-08 17:34:18Z cfi $
#
# OPAC KpwinSQL Version Detection
#
# Authors:
# Tushar Khelge <ktushar@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.808098");
  script_version("$Revision: 5900 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-04-08 19:34:18 +0200 (Sat, 08 Apr 2017) $");
  script_tag(name:"creation_date", value:"2016-06-28 13:02:55 +0530 (Tue, 28 Jun 2016)");
  script_name("OPAC KpwinSQL Version Detection");

  script_tag(name : "summary" , value : "Detection of installed version of
  OPAC KpwinSQL.

  This script sends HTTP GET request and try to ensure the presence of OPAC KpwinSQL
  from the response.");

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
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

##Variable Initialisation
opac_port = 0;
url = "";
dir = "";
sndReq = "";
rcvRes = "";

opac_port = get_http_port(default:80);
if(! can_host_php(port:opac_port)) exit(0);

foreach dir(make_list_unique("/", "/OPAC", "/kpwinSQL", "/OPAC-kpwinSQL",  cgi_dirs(port:opac_port)))
{
  install = dir;
  if( dir == "/" ) dir = "";
  url = dir + '/index.php';
  rcvRes = http_get_cache(item:url, port:opac_port);

  ## Confirm the application
  if(rcvRes && "KPWIN" >< rcvRes && rcvRes =~ "<title>WWW OPAC.*KpwinSQL </title" &&
     "OPACSQL" >< rcvRes && rcvRes =~ "HTTP/1.. 200")
  {
    version = "unknown";

    ## Set KB
    set_kb_item(name:"KpwinSQL/Installed", value:TRUE);

    ## build cpe and store it as host_detail
    cpe = "cpe:/a:opac:kpwinsql";

    register_product(cpe:cpe, location:install, port:opac_port);

    log_message(data:build_detection_report(app:"KpwinSQL",
                                            version:version,
                                            install:install,
                                            cpe:cpe,
                                            concluded:version),
                                            port:opac_port);
    exit(0);
  }
}
