###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_struts_detect.nasl 5516 2017-03-08 13:28:03Z mime $
#
# Apache Struts Version Detection
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Updated By: Madhuri D <dmadhuri@secpod.com> on 2010-09-09
# - Modified the script to detect the recent versions
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
  script_oid("1.3.6.1.4.1.25623.1.0.800276");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 5516 $");
  script_tag(name:"last_modification", value:"$Date: 2017-03-08 14:28:03 +0100 (Wed, 08 Mar 2017) $");
  script_tag(name:"creation_date", value:"2009-04-23 08:16:04 +0200 (Thu, 23 Apr 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Apache Struts Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"The script detects the version of Apache Struts and sets the
  result in KB.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

asPort = get_http_port( default:8080 );

foreach dir( make_list_unique("/", "/struts", cgi_dirs( port:asPort ) ) ) 
{
  install = dir;
  if( dir == "/" ) dir = "";


  ## For some versions path has "/docs/docs/" 
  ## While for some versions path has only "/docs"
  foreach url (make_list(dir + "/docs/docs", dir +"/docs"))
  {

    # Main doc page
    sndReq = http_get( item:url + "/index.html", port:asPort);
    rcvRes = http_keepalive_send_recv( port:asPort, data:sndReq );

    ##Home Doc page
    sndReq2 = http_get(item:url + "/WW/cwiki.apache.org/WW/home.html", port:asPort);
    rcvRes2 = http_keepalive_send_recv(port:asPort, data:sndReq2);

    ##For some versions path is different
    if(rcvRes2 !~ "HTTP/1.. 200 OK")
    {
      sndReq = http_get( item:url + "/home.html", port:asPort );
      rcvRes2 = http_keepalive_send_recv( port:asPort, data:sndReq);
    }

    # guides doc page
    sndReq3 = http_get(item:url + "/WW/cwiki.apache.org/WW/guides.html", port:asPort);
    rcvRes3 = http_keepalive_send_recv(port:asPort, data:sndReq3);

    ##For some versions path is different
    if(rcvRes3 !~ "HTTP/1.. 200 OK")
    {
      sndReq = http_get(item:url + "/guides.html", port:asPort );
      rcvRes3 = http_keepalive_send_recv( port:asPort, data:sndReq );
    }

    ## searching for Struts version in different possible files
    sndReq4 = http_get( item:dir + "/src/src/site/xdoc/index.xml", port:asPort );
    rcvRes4 = http_keepalive_send_recv( port:asPort, data:sndReq3 );

    sndReq5 = http_get( item:dir + "/utils.js", port:asPort );
    rcvRes5 = http_keepalive_send_recv( port:asPort, data:sndReq5 );

    if(("Struts" >< rcvRes && ("Apache" >< rcvRes || "apache" >< rcvRes ) ) ||
        ( "Getting Started" >< rcvRes2 && "Home" >< rcvRes2 && "Distributions" >< rcvRes2 ) ||
        ( "Migration Guide" >< rcvRes3 && "Core Developers Guide" >< rcvRes3 && "Release Notes" >< rcvRes3 ) ||
          "Apache Struts" >< rcvRes4  || "var StrutsUtils =" >< rcvRes5 ) {

      version = "unknown";
 
      strutsVer = eregmatch( pattern:">Version Notes (([0-9]+).([0-9]+).([0-9]+))", string:rcvRes3);
      if(isnull( strutsVer[1] ) ) 
      {
        strutsVer = eregmatch( pattern:"Release Notes ([0-9]\.[0-9.]+)", string:rcvRes2);
        if(isnull(strutsVer[1]))
        {
          strutsVer = eregmatch( pattern:"Release Notes ([0-9]\.[0-9.]+)", string:rcvRes3 );
          if( isnull( strutsVer[1] ) ) 
          {
            strutsVer = eregmatch( pattern:">version ([0-9.]+)", string:rcvRes4 );
            if( ! isnull( strutsVer[1] ) ) version = strutsVer[1];
          } else {
            version = strutsVer[1];
          }
        } else {
          version = strutsVer[1];
        }
      } else { 
        version = strutsVer[1];
      }
      
      tmp_version = version + " under " + install;
      set_kb_item( name:"www/" + asPort + "/Apache/Struts", value:tmp_version);
      set_kb_item( name:"ApacheStruts/installed", value:TRUE);

      ## Build CPE
      cpe = build_cpe( value:version, exp: "^([0-9.]+)", base: "cpe:/a:apache:struts:" );
      if(isnull(cpe))
        cpe = 'cpe:/a:apache:struts';
  
      register_product(cpe: cpe, location: install, port: asPort);
 
      log_message( data: build_detection_report( app:"Apache Struts",
                                                 version: version,
                                                 install: install,
                                                 cpe: cpe,
                                                 concluded: tmp_version),
                                                 port: asPort);
      exit(0);
    }
  }
}
exit(0);
