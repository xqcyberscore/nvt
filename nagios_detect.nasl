###############################################################################
# OpenVAS Vulnerability Test
# $Id: nagios_detect.nasl 5737 2017-03-27 14:18:12Z cfi $
#
# Nagios Detection
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
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

tag_summary = "Detection of Nagios.
                    
The script sends a connection request to the server and attempts to
extract the version number from the reply.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.100186";

if(description)
{
 script_oid(SCRIPT_OID);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 5737 $");
 script_tag(name:"last_modification", value:"$Date: 2017-03-27 16:18:12 +0200 (Mon, 27 Mar 2017) $");
 script_tag(name:"creation_date", value:"2009-05-06 14:55:27 +0200 (Wed, 06 May 2009)");
 script_tag(name:"cvss_base", value:"0.0");
 script_name("Nagios Detection");  
 script_category(ACT_GATHER_INFO);
 script_tag(name:"qod_type", value:"remote_banner");
 script_family("Product detection");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

files = make_list( "/main.php", "/main.html" );

foreach dir( make_list_unique( "/nagios", "/monitoring", cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";

  foreach file( files ) {

   url = dir + file; 
   buf = http_get_cache(item:url, port:port);
   if( buf == NULL )continue;

   if( egrep(pattern: '<TITLE>Nagios( Core)?', string: buf, icase: TRUE) &&
       (egrep(pattern: 'Nagios( Core)? is licensed under the GNU', string: buf, icase: TRUE) ||
        "Monitored by Nagios" >< buf) ||
       'Basic realm="Nagios Access"' >< buf
       )
   { 
      vers = string("unknown");

      ### try to get version.
      version = eregmatch(string: buf, pattern: 'Version ([0-9.]+)',icase:TRUE);
    
      if ( !isnull(version[1]) ) {
         vers=version[1];
      } 

      tmp_version = string(vers," under ", install);
      set_kb_item(name: string("www/", port, "/nagios"), value: tmp_version);
      set_kb_item(name:"nagios/installed", value:TRUE);

      ## build cpe and store it as host_detail
      cpe = build_cpe(value: tmp_version, exp:"^([0-9.]+)", base:"cpe:/a:nagios:nagios:");
      if(isnull(cpe))
        cpe = 'cpe:/a:nagios:nagios';

      register_product(cpe:cpe, location:install, nvt:SCRIPT_OID, port:port);
      log_message(data: build_detection_report(app:"Nagios", version:vers, install:install, cpe:cpe, concluded: version[0]),
                  port:port);
      exit(0);

   }
  }
}

exit(0);
