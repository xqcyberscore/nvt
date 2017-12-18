###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_canon_printers_detect.nasl 8141 2017-12-15 12:43:22Z cfischer $
#
# Canon Printer Detection
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.803719");
  script_version("$Revision: 8141 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-12-15 13:43:22 +0100 (Fri, 15 Dec 2017) $");
  script_tag(name:"creation_date", value:"2013-06-20 13:42:47 +0530 (Thu, 20 Jun 2013)");
  script_name("Canon Printer Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value :"Detection of Canon Printers.

  The script sends a connection request to the remote host and attempts
  to detect if the remote host is a Canon printer.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

port = "";
req = "";
buf = "";
firm_ver = "";
printer_model = "";

port = get_http_port(default:80);

buf = http_get_cache(item:"/index.html", port:port);

## Confirm the application
# If updating here please also update check in dont_print_on_printers.nasl
if(('>Canon' >< buf && ">Copyright CANON INC" ><  buf && "Printer" >< buf) || "CANON HTTP Server" >< buf)
{
   set_kb_item(name:"target_is_printer", value:1);
   set_kb_item(name:"canon_printer/installed", value:1);
   set_kb_item(name:"canon_printer/port", value: port);

   pref = get_kb_item("global_settings/exclude_printers");
   if( pref  == "yes" )
   {
       set_kb_item( name:"Host/dead", value:TRUE );
       log_message( port:port, data:'The remote host is a printer. The scan has been disabled against this host.\nIf you want to scan the remote host, uncheck the "Exclude printers from scan" option and re-scan it.');
   }

   ## Get the model name
   printer_model = eregmatch(pattern:">(Canon.[A-Z0-9]+).[A-Za-z]+<", string: buf);
   if(printer_model[1])
   {
     set_kb_item(name:"canon_printer_model", value:printer_model[1]);

     cpe_printer_model = tolower(printer_model[1]);
     cpe = 'cpe:/h:canon:' + cpe_printer_model;
     cpe = str_replace(string:cpe,find:" ", replace:"_");

     ## Get the Firmware version
     firm_ver = eregmatch(pattern:"nowrap>([0-9.]+)</td>", string: buf);
     if(firm_ver[1])
     {
       set_kb_item(name:"canon_printer/firmware_ver", value: firm_ver[1]);
       cpe = cpe + ":" + firm_ver[1];
     }

     register_product(cpe:cpe, location:port + '/tcp', port:port);

     log_message(data: "The remote Host is a  " + printer_model[1] +
                 " printer device.\nCPE: " + cpe + "\nConcluded: " +
                 printer_model[1], port:port);

      exit(0);

  }
}
