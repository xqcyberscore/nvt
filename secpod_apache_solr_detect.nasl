###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_apache_solr_detect.nasl 5829 2017-04-03 07:00:29Z cfi $
#
# Apache Solr Version Detection
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Updated by: kashinath T <tkashinath@sepcod.com>
# Updated to support detection of newer versions.
# 
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.903506");
  script_version("$Revision: 5829 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-04-03 09:00:29 +0200 (Mon, 03 Apr 2017) $");
  script_tag(name:"creation_date", value:"2014-01-29 13:13:35 +0530 (Wed, 29 Jan 2014)");
  script_name("Apache Solr Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 SecPod");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 8983);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detection of installed version of Apache Solr.

  This script sends HTTP GET request and try to get the version from the
  response, and sets the result in KB.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

solrPort = get_http_port( default:8983 );

foreach dir( make_list_unique( "/", "/solr", "/apachesolr", cgi_dirs( port:solrPort ) ) )
{
  if( dir == "/" ) dir = "";

  rcvRes = http_get_cache( item: dir + "/" , port:solrPort );

  #Confirm Application
  if( rcvRes =~ "HTTP/1.. 200" && (">Solr Admin<" >< rcvRes || "Solr admin page" >< rcvRes ))
  {
    req = http_get( item: dir + "/admin/registry.jsp", port:solrPort );
    rcvRes = http_keepalive_send_recv( port:solrPort, data:req, bodyonly:TRUE );

    if(rcvRes && "lucene-spec-version" >< rcvRes)
    {
      ver = eregmatch( string:rcvRes, pattern:"lucene-spec-version>([0-9.]+)", icase:TRUE );
      if(ver[1] != NULL ){
        version = ver[1];
      }
    
      if(!version)
      {
        req = http_get( item: dir + "/#/", port:solrPort );
        rcvRes1 = http_keepalive_send_recv( port:solrPort, data:req, bodyonly:TRUE );
        if(rcvRes1){
          ver = eregmatch( string:rcvRes1, pattern:'<script src.*=([0-9.]+).*></script>', icase:TRUE );
        } 
     
        if( ver[1] != NULL ){
          version = ver[1];
        }        
      } else {
        version = "Unknown";
      } 

      set_kb_item( name:"Apache/Solr/Version", value:version );
      set_kb_item(name:"Apache/Solr/Installed", value:TRUE);
 
      ## build cpe and store it as host_detail
      cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:apache:solr:" );
      if( ! cpe )
        cpe = "cpe:/a:apache:solr";

      register_product( cpe:cpe, location:dir, port:solrPort );

      log_message( data: build_detection_report( app:"Apache Solr",
                                                 version:version,
                                                 install:dir,
                                                 cpe:cpe,
                                                 concluded:version ),
                                               port:solrPort );
    }
  }
}
exit(0);
