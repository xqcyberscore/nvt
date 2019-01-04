###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_xerox_printer_detect.nasl 12940 2019-01-04 09:23:20Z ckuersteiner $
#
# Xerox Printer Detection (HTTP)
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
  script_version("$Revision: 12940 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-04 10:23:20 +0100 (Fri, 04 Jan 2019) $");
  script_tag(name:"creation_date", value:"2013-01-30 14:31:24 +0100 (Wed, 30 Jan 2013)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_name("Xerox Printer Detection (HTTP)");

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
    set_kb_item(name: "xerox_printer/detected", value:TRUE);
    set_kb_item(name: "xerox_printer/http/detected", value:TRUE);
    set_kb_item(name: "xerox_printer/http/port", value: port);
    set_kb_item(name: "xerox_printer/http/" + port + "/model", value: model);

    # AltaLink
    # <tr ><td>Device Software:</td><td>100.002.008.05702</td></tr>
    vers = eregmatch(pattern: "Device Software:</td><td>([0-9.]+)<", string: buf);
    if (!isnull(vers[1])) {
      set_kb_item(name: "xerox_printer/http/" + port + "/fw_version", value: vers[1]);
      set_kb_item(name: "xerox_printer/http/" + port + "/concluded", value: vers[0]);
      set_kb_item(name: "xerox_printer/http/" + port + "/concludedUrl", value: url);
    }
    else {
      # DocuPrint
      # Version</td><td class=std_2>201210101131</td></tr>
      vers = eregmatch(pattern: "Version</td><td class=std_2>([0-9]+)<", string: buf);
      if (!isnull(vers[1])) {
        set_kb_item(name: "xerox_printer/http/" + port + "/fw_version", value: vers[1]);
        set_kb_item(name: "xerox_printer/http/" + port + "/concluded", value: vers[0]);
        set_kb_item(name: "xerox_printer/http/" + port + "/concludedUrl", value: url);
      }
    }

    exit(0);
  }

  else if("HTTP/1.1 401" >< buf && "CentreWare Internet Services" >< buf)  {

    set_kb_item(name:"target_is_printer", value:TRUE);
    set_kb_item(name:"xerox_printer/detected", value:TRUE);
    set_kb_item(name: "xerox_printer/http/detected", value:TRUE);
    set_kb_item(name: "xerox_printer/http/port", value: port);

    exit(0);
  }
}

exit(0);
