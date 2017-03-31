###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_mediawiki_detect.nasl 2793 2016-03-08 10:38:36Z cfi $
#
# MediaWiki Version Detection
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Updated By : Sooraj KS <kssooraj@secpod.com> on 2010-04-27
#   -Modified the regex for detecting beta versions.
#
# Updated By : Antu Sanadi<santu@secpod.com> on 2011-03-o3
#  - Modified the application confirmation logic
#
# Updated By : Madhuri D<dmadhuri@secpod.com> on 2011-05-31
#  - Updated the KB item to save directory path
#
# Updated By : Madhuri D<dmadhuri@secpod.com> on 2012-07-09
#   Updated according to CR 57 and used build_detection_report
#
# Updated By: Thanga Prakash S <tprakash@secpod.com> on 2013-10-01
# According to new style script_tags.
#
# Copyright (c) 2008 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.900420");
  script_version("$Revision: 2793 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2016-03-08 11:38:36 +0100 (Tue, 08 Mar 2016) $");
  script_tag(name:"creation_date", value:"2008-12-29 13:55:43 +0100 (Mon, 29 Dec 2008)");
  script_name("MediaWiki Version Detection");
  script_summary("Checks for the presence of MediaWiki");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 SecPod");
  script_family("Product detection");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detection of installed version of MediaWiki

  This script sends HTTP GET request and try to get the version from the
  response, and sets the result in KB.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

## start script
port = get_http_port( default:80 );

if( ! can_host_php( port:port ) ) exit( 0 );

foreach dir( make_list_unique("/wiki", "/mediawiki", cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";

  sndReq = http_get( item: dir + "/index.php/Special:Version", port:port );
  rcvRes = http_keepalive_send_recv( port:port, data:sndReq );

  if( ( "Powered by" >< rcvRes || "powered by" >< rcvRes ) && "MediaWiki" >< rcvRes && rcvRes =~ "HTTP/1.. 200" ) {

    version = "unknown";

    ver = eregmatch(pattern:"MediaWiki ([0-9.]+)(.?([a-zA-Z0-9]+))?", string:rcvRes);

    if( ver[1] != NULL ) {
      if( ver[3] != NULL ) {
        version = ver[1] + "." + ver[2];
      } else {
        version = ver[1];
      }
    }

    tmp_version = version + " under " + install;
    set_kb_item( name:"MediaWiki/Version", value:tmp_version );
    set_kb_item( name:"mediawiki/installed", value:TRUE );

    cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:mediawiki:mediawiki:" );
    if( isnull( cpe ) )
      cpe = 'cpe:/a:mediawiki:mediawiki';

    register_product( cpe:cpe, location:install, port:port );

    log_message( data:build_detection_report( app:"MediaWiki",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              concluded:ver[0] ),
                                              port:port );
  }
}

exit( 0 );