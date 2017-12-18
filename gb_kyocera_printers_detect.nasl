###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_kyocera_printers_detect.nasl 8137 2017-12-15 11:26:42Z cfischer $
#
# Kyocera Printer Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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
  script_oid("1.3.6.1.4.1.25623.1.0.103707");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 8137 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-15 12:26:42 +0100 (Fri, 15 Dec 2017) $");
  script_tag(name:"creation_date", value:"2013-05-08 11:31:24 +0100 (Wed, 08 May 2013)");
  script_name("Kyocera Printer Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detection of Kyocera Printers.

  The script sends a connection request to the remote host and
  attempts to detect if the remote host is a Kyocera printer.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("kyocera_printers.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

port = get_http_port(default:80);

urls = get_ky_detect_urls();

foreach url(keys(urls)) {

  pattern = url;
  url = urls[url];

  buf = http_get_cache(item:url, port:port);

  if(kyo = eregmatch(pattern:pattern, string: buf, icase:TRUE)) {

    if(!isnull(kyo[1])) {

      concluded = kyo[0];
      model     = kyo[1];

     set_kb_item(name:"target_is_printer", value:1);
     set_kb_item(name:"kyocera_printer/installed", value:1);
     set_kb_item(name:"kyocera_printer/port", value: port);
     set_kb_item(name:"kyocera_model", value:model);

     cpe_model = tolower(model);

     cpe = 'cpe:/h:kyocera:' + cpe_model;
     cpe = str_replace(string:cpe,find:" ", replace:"_");

     register_product(cpe:cpe, location:port + '/tcp', port:port);

     log_message(data: "The remote Host is a Kyocera " + model + " printer device.\nCPE: " + cpe + "\nConcluded: " + concluded, port:port);

     pref = get_kb_item("global_settings/exclude_printers");
     if( pref  == "yes" ) {
       set_kb_item( name:"Host/dead", value:TRUE );
       log_message( port:port, data:'The remote host is a printer. The scan has been disabled against this host.\nIf you want to scan the remote host, uncheck the "Exclude printers from scan" option and re-scan it.');
     }
     exit(0);
    }
  }
}

exit(0);
