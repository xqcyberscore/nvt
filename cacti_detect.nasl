###############################################################################
# OpenVAS Vulnerability Test
# $Id: cacti_detect.nasl 2622 2016-02-09 13:03:15Z antu123 $
#
# Cacti Detection
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

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.100204");
 script_version("$Revision: 2622 $");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_tag(name:"last_modification", value:"$Date: 2016-02-09 14:03:15 +0100 (Tue, 09 Feb 2016) $");
 script_tag(name:"creation_date", value:"2009-05-16 14:32:16 +0200 (Sat, 16 May 2009)");
 script_name("Cacti Detection");

 script_tag(name: "summary" , value: "Detection of Cacti.

 The script sends a connection request to the server and attempts to
 extract the version number from the reply");

 script_tag(name:"qod_type", value:"remote_banner");

 script_summary("Checks for the presence of Cacti");
 script_category(ACT_GATHER_INFO);
 script_family("Product detection");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");
include("cpe.inc");
include("host_details.inc");

## Constant values
cacti_port = get_http_port(default:80);

## Checking port state
if(!get_port_state(cacti_port))exit(0);

## Checking host support php
if(!can_host_php(port:cacti_port)) exit(0);

foreach dir (make_list("/cacti","/monitoring", cgi_dirs()))
{
  url = string(dir, "/index.php");
  req = http_get(item:url, port:cacti_port);
  buf = http_send_recv(port:cacti_port, data:req, bodyonly:FALSE);

  if( buf == NULL )continue;

  if( egrep(pattern: 'Login to Cacti', string: buf, icase: TRUE) &&
       egrep(pattern: "Set-Cookie: Cacti", string:buf) )
  {

    if(strlen(dir)>0) {
       install=dir;
    }
    else{
      install=string("/");
    }

    vers = string("unknown");

    ### try to get version.
    url = string(dir, "/docs/CHANGELOG");
    req = http_get(item:url, port:cacti_port);
    buf = http_keepalive_send_recv(port:cacti_port, data:req, bodyonly:TRUE);

    if("Cacti CHANGELOG" >< buf && "-bug#" >< buf) {

      version = eregmatch(string: buf, pattern: "([0-9.]+[a-z]{0,1})",icase:TRUE);

      if ( !isnull(version[1]) ) {
        vers=version[1];
      }
    }

    tmp_version = string(vers, " under ", install);
    set_kb_item(name: string("www/", cacti_port, "/cacti"), value: tmp_version);
    set_kb_item(name:"cacti/installed", value:TRUE);

    ## build cpe and store it as host_detail
    cpe = build_cpe(value:tmp_version, exp:"([0-9.]+[a-z]{0,1})", base:"cpe:/a:cacti:cacti:");
    if(isnull(cpe))
      cpe = 'cpe:/a:cacti:cacti';

    register_product(cpe:cpe, location:install, port:cacti_port);

    log_message(data: build_detection_report(app:"Cacti",
                                             version:vers,
                                             install:install,
                                             cpe:cpe,
                                             concluded: vers),
                                             port:cacti_port);

  }
}
