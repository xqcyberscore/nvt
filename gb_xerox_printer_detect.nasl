###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_xerox_printer_detect.nasl 9972 2018-05-26 12:31:48Z cfischer $
#
# Xerox Printer Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.103648");
  script_version("$Revision: 9972 $");
  script_tag(name:"last_modification", value:"$Date: 2018-05-26 14:31:48 +0200 (Sat, 26 May 2018) $");
  script_tag(name:"creation_date", value:"2013-01-30 14:31:24 +0100 (Wed, 30 Jan 2013)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Xerox Printer Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  # nb: Don't use http_version.nasl as the Detection should run as early
  # as possible if the printer should be marked dead as requested.
  script_dependencies("find_service.nasl", "httpver.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detection of Xerox Printers.

  The script sends a connection request to the remote host and
  attempts to detect if the remote host is a Xerox printer.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("xerox_printers.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("host_details.inc");

port = get_http_port(default:80);

urls = get_xerox_detect_urls();

foreach url (keys(urls)) {

  buf = http_get_cache(item:url, port:port);

  if(match = eregmatch(pattern:urls[url], string:buf, icase:TRUE)) {

    if(isnull(match[1]))continue;

    model = chomp(match[1]);

    set_kb_item(name:"target_is_printer", value:TRUE);
    set_kb_item(name:"xerox_printer/installed", value:TRUE);
    set_kb_item(name:"xerox_model", value:model);

    cpe = build_xerox_cpe(model:model);

    register_product(cpe:cpe, location:port + "/tcp", port:port);

    log_message(data:"The remote Host is a Xerox " + model + " printer device.\nCPE: " + cpe + "\nConcluded: " + match[0], port:port);
    pref = get_kb_item("global_settings/exclude_printers");
    if(pref == "yes") {
      log_message(port:port, data:'The remote host is a printer. The scan has been disabled against this host.\nIf you want to scan the remote host, uncheck the "Exclude printers from scan" option and re-scan it.');
      set_kb_item(name:"Host/dead", value:TRUE);
    }
    exit(0);
  }

  else if("HTTP/1.1 401" >< buf && "CentreWare Internet Services" >< buf)  {

    set_kb_item(name:"target_is_printer", value:TRUE);
    set_kb_item(name:"xerox_printer/installed", value:TRUE);
    set_kb_item(name:"xerox_model", value:"generic_basic_auth");

    cpe = "cpe:/h:xerox";
    register_product(cpe:cpe, location:port + "/tcp", port:port);

    log_message(port:port, data:"The remote Host is an unknown xerox printer device.\nCPE: " + cpe + "\n");

    pref = get_kb_item("global_settings/exclude_printers");
    if(pref == "yes") {
      log_message(port:port, data:'The remote host is a printer. The scan has been disabled against this host.\nIf you want to scan the remote host, uncheck the "Exclude printers from scan" option and re-scan it.');
      set_kb_item(name:"Host/dead", value:TRUE);
    }
    exit(0);
  }
}

exit(0);
