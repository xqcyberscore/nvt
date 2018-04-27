###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_zarafa_webapp_detect.nasl 9633 2018-04-26 14:07:08Z jschulte $
#
# Zarafa WebApp sDetection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2014 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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
  script_oid("1.3.6.1.4.1.25623.1.0.105137");
  script_version ("$Revision: 9633 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-04-26 16:07:08 +0200 (Thu, 26 Apr 2018) $");
  script_tag(name:"creation_date", value:"2014-12-08 10:46:34 +0100 (Mon, 08 Dec 2014)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Zarafa WebApp Detection");

  script_tag(name: "summary" , value: "The script sends a connection
  request to the server and attempts to extract the version number
  from the reply.");


  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
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

port = get_http_port( default:80 );

foreach url (make_list("", "/", "/webapp"))
{
  req = http_get( item:url, port:port );
  buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );
  if( buf == NULL )continue;

  if( "<title>Zarafa WebApp" >< buf )
  {
    set_kb_item(name:"zarafa_webapp/installed",value:TRUE);
    replace_kb_item(name:"zarafa/installed",value:TRUE);

    vers = 'unknown';
    version = eregmatch( pattern:'<span id="version">WebApp ([^ <]+)( - ZCP ([^<]+))?</span>', string:buf );

    if( ! isnull( version[1] ) )
    {
      vers = version[1];
      set_kb_item(name:"zarafa_webapp/installed",value:TRUE);
      cpe = build_cpe( value:vers, exp:"^([0-9.-]+)", base:"cpe:/a:zarafa:webapp:" );
      if( isnull( cpe ) )
      cpe = "cpe:/a:zarafa:webapp";
      cpe = str_replace( string:cpe, find:"-", replace:".");

      register_product( cpe:cpe, location:url, port:port );

      log_message( data: build_detection_report( app:"Zarafa WebApp",
                                                 version:vers,
                                                 install:url,
                                                 cpe:cpe,
                                                 concluded: version[0] ),
                                                 port:port );
    }

    if(!isnull(version[3]))
    {
      vers_zcp = version[3];
      set_kb_item(name:"zarafa_zcp/installed",value:TRUE);
      replace_kb_item(name:"zarafa/installed", value:TRUE);

      cpe = build_cpe( value:vers_zcp, exp:"^([0-9.-]+)", base:"cpe:/a:zarafa:zarafa_collaboration_platform:" );
      if( isnull( cpe ) )
      cpe = "cpe:/a:zarafa:zarafa_collaboration_platform";

      cpe = str_replace( string:cpe, find:"-", replace:".");
      register_product( cpe:cpe, location:url, port:port );

      log_message( data: build_detection_report( app:"Zarafa Collaboration Platform",
                                                 version:vers_zcp,
                                                 install:url,
                                                 cpe:cpe,
                                                 concluded: version[0] ),
                                                 port:port );
    }
  }
}
