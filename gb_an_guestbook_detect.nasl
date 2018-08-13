###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_an_guestbook_detect.nasl 10898 2018-08-10 13:38:13Z cfischer $
#
# AN Guestbook Version Detection
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.800523");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 10898 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 15:38:13 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2009-07-07 11:58:41 +0200 (Tue, 07 Jul 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("AN Guestbook Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This script detects the installed version of AN Guestbook and
  sets the result in KB.");

  script_tag(name:"qod_type", value:"remote_banner");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

wwwPort = get_http_port(default:80);

if( !can_host_php( port:wwwPort ) ) exit( 0 );

foreach dir (make_list_unique("/ag", "/ang", "/guestbook", "/anguestbook", cgi_dirs(port:wwwPort)))
{

  install = dir;
  if(dir == "/") dir = "";

  rcvRes = http_get_cache(item: dir + "/index.php", port:wwwPort);

  if(("AG" >< rcvRes) && ("version" >< rcvRes)){
    angVer = eregmatch(pattern:"AG(</a>)? - version ([0-9.]+)", string:rcvRes);
  }
  else
  {
    sndReq = http_get(item: dir + "/ang/index.php", port:wwwPort);
    rcvRes = http_keepalive_send_recv(port:wwwPort, data:sndReq);

    if(("Powered by" >< rcvRes) && ("ANG" >< rcvRes)){
      angVer = eregmatch(pattern:"Powered by.*ANG(</a>)? ([0-9.]+)", string:rcvRes);
    }
  }

  if(angVer[2]!= NULL)
  {
    tmp_version = angVer[2] + " under " + install;
    set_kb_item(name:"www/" + wwwPort + "/AN-Guestbook", value:tmp_version);

    cpe = build_cpe(value:angVer[2], exp:"^([0-9.]+)", base:"cpe:/a:an_guestbook:an_guestbook:");
    if( isnull( cpe ) )
      cpe = 'cpe:/a:an_guestbook:an_guestbook';

    register_product( cpe:cpe, location:install, port:wwwPort );

    log_message( data: build_detection_report( app:"An Guest Book",
                                               version:angVer[2],
                                               install:install,
                                               cpe:cpe,
                                               concluded: angVer[0]),
                                               port:wwwPort);

  }
}
