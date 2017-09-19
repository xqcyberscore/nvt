###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_moinmoin_wiki_detect.nasl 7166 2017-09-18 09:14:09Z cfischer $
#
# MoinMoin Wiki Version Detection
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.800170");
  script_version("$Revision: 7166 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-09-18 11:14:09 +0200 (Mon, 18 Sep 2017) $");
  script_tag(name:"creation_date", value:"2010-03-05 10:09:57 +0100 (Fri, 05 Mar 2010)");
  script_name("MoinMoin Wiki Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detection of MoinMoin Wiki.

  This script detects the installed version of MoinMoin Wiki
  and sets the result in KB.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

## set the kb and CPE
function _SetCpe( vers, port, dir, concl ) {

  local_var vers, port, tmp_version, dir, concl;

  ## set the kb
  tmp_version = vers + " under " + dir;
  set_kb_item( name: "www/" + port + "/moinmoinWiki", value:tmp_version );
  set_kb_item( name: "moinmoinWiki/installed", value:TRUE );

  ## build cpe
  cpe = build_cpe( value:vers, exp:"^([0-9.]+)", base:"cpe:/a:moinmo:moinmoin:" );
  if( isnull( cpe ) )
    cpe = 'cpe:/a:moinmo:moinmoin';

  ## register the product
  register_product( cpe:cpe, location:dir, port:port );
  log_message( data:build_detection_report( app:"moinmoinWiki",
                                            version:vers,
                                            install:dir,
                                            cpe:cpe,
                                            concluded:concl ),
                                            port:port );
}

port = get_http_port( default:8080 );

## Get the banner to check version
banner = get_http_banner( port:port );
if( "erver: MoinMoin" >< banner ) {
  bannerIdentified = TRUE;
  vers = eregmatch( pattern:"erver: MoinMoin ([0-9.a-z]+) release", string:banner );
  if( vers[1] ) {
    bannerVersion = TRUE;
    _SetCpe( vers:vers[1], port:port, dir:"/", concl:vers[0] );
  }
}

rootInstalled = FALSE;

foreach dir( make_list_unique( "/", "/Moin", "/moin", "/wiki", cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";
  if( rootInstalled ) break;

  req1 = http_get( item:dir + "/SystemInfo", port:port );
  res1 = http_keepalive_send_recv( port:port, data:req1 );

  res2 = http_get_cache( item:"/", port:port );

  ## Check for MoinMoin and SystemInfo in the response
  if( ( res1 =~ "HTTP/1.. 200" && "SystemInfo" >< res1 && ">MoinMoin" >< res1 ) ||
        "This site uses the MoinMoin Wiki software." >< res2 || ">MoinMoin Powered<" >< res2 ) {

    version = "unknown";
    flag = TRUE;
    if( install == "/" ) rootInstalled = TRUE;
    if( bannerVersion && install == "/" ) continue;

    ## Get MoinMoin Wiki Version
    vers = eregmatch( pattern:"(Release|Version) ([0-9.a-z]+) \[Revision release\]", string:res1 );
    if( vers[2] ) version = vers[2];
    _SetCpe( vers:version, port:port, dir:install, concl:vers[0] );
  }
}

if( bannerIdentified && ! flag ) {
  _SetCpe( vers:version, port:port, dir:install, concl:vers[0] );
}

exit( 0 );