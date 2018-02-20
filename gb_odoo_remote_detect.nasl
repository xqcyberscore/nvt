###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_odoo_remote_detect.nasl 8845 2018-02-16 10:57:50Z santu $
#
# Odoo Management Software Remote Detection
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.812511");
  script_version("$Revision: 8845 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-02-16 11:57:50 +0100 (Fri, 16 Feb 2018) $");
  script_tag(name:"creation_date", value:"2018-02-08 11:46:24 +0530 (Thu, 08 Feb 2018)");
  script_name("Odoo Management Software Remote Detection");

  script_tag(name:"summary", value:"Detection of installed version of
  Odoo management software.
  
  This script sends HTTP GET request and try to get the version from the
  response.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}


include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

odPort = 0;
rcvRes = "";
sndReq = "";
version = "";

if(!odPort = get_http_port(default:80)){
  exit(0);
}

foreach dir(make_list_unique("/", "/Odoo", "/odoo_cms", "/odoo_cms", "odoo_cmr","CMR",  cgi_dirs(port:odPort))) 
{
  install = dir;
  if( dir == "/" ) dir = "";

  sndReq = http_get(item: dir + "/web/login", port: odPort);
  rcvRes = http_keepalive_send_recv(port:odPort, data:sndReq);

  if("Log in with Odoo.com" >< rcvRes && (rcvRes =~ '(P|p)owered by.*>Odoo' || 'content="Odoo' >< rcvRes) &&
     ">Log in" >< rcvRes)
  {
    version = "Unknown";
    set_kb_item(name:"Odoo/Detected", value:TRUE);

    cpe = "cpe:/a:odoo:odoo";

    register_product(cpe:cpe, location:install, port:odPort);

    log_message(data:build_detection_report(app:"Odoo",
                                            version:version,
                                            install:install,
                                            cpe:cpe,
                                            concluded:version),
                                            port:odPort);
    exit(0);
  }
}
exit(0);
