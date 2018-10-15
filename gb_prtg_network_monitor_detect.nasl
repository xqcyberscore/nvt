###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_prtg_network_monitor_detect.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# PRTG Network Monitor Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
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

tag_summary = "This host is running the PRTG Network Monitor.";

if (description)
{

  script_oid("1.3.6.1.4.1.25623.1.0.103048");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-01-27 12:55:42 +0100 (Thu, 27 Jan 2011)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("PRTG Network Monitor Detection");

  script_tag(name:"summary", value:"Detection of PRTG Network Monitor

The script attempts to identify Opmantek NMIS and to extract the version number.");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 443);
  script_mandatory_keys("PRTG/banner");

  script_xref(name:"URL", value:"http://www.paessler.com/prtg");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:443);

banner = get_http_banner(port:port);
if(!banner || "Server: PRTG/" >!< banner)exit(0);

url = string("/index.htm");
buf = http_get_cache(item:url, port:port);

if(egrep(pattern: "PRTG Network Monitor", string: buf, icase: TRUE))
{
   install = "/";

   vers = "unknown";
   version = eregmatch(string: buf, pattern: "Server: PRTG/([0-9.]+)",icase:TRUE);

   if ( !isnull(version[1]) ) {
      vers = version[1];
   }

   set_kb_item(name: string("www/", port, "/prtg_network_monitor"), value: string(vers," under ",install));
   set_kb_item(name: "prtg_network_monitor/installed", value: TRUE);

   cpe = build_cpe(value: vers, exp: "^([0-9.]+)", base: "cpe:/a:paessler:prtg_network_monitor:");
   if (!cpe)
     cpe = "cpe:/a:paessler:prtg_network_monitor";

   register_product(cpe: cpe, location: install, port: port);

   log_message(data: build_detection_report(app: "PRTG Network Monitor", version: vers, install: install,
                                            cpe: cpe, concluded: version[0]),
               port: port);

   exit(0);
}

exit(0);

