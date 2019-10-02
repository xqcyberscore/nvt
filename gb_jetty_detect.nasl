###############################################################################
# OpenVAS Vulnerability Test
#
# Jetty Version Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.800953");
  script_version("2019-09-26T07:29:46+0000");
  script_tag(name:"last_modification", value:"2019-09-26 07:29:46 +0000 (Thu, 26 Sep 2019)");
  script_tag(name:"creation_date", value:"2009-10-20 14:26:56 +0200 (Tue, 20 Oct 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Jetty Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.eclipse.org/jetty/");

  script_tag(name:"summary", value:"Detection of Jetty Web Server.

  The script sends a connection request to the server and attempts to
  extract the version number from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

function jetty_extract_version( ver ) {

  local_var ver;
  local_var version;

  if( ! isnull( ver[1] ) ) {
    if( ! isnull( ver[2] ) ) {
      ver[2] = ereg_replace( pattern:"^v", string:ver[2], replace:"" );
      if( ver[1] =~ "\.$" )
        version = ver[1] + ver[2];
      else
        version = ver[1] + "." + ver[2];
    } else {
      ver[1] = ereg_replace( pattern:"\.$", string:ver[1], replace:"" );
      version = ver[1];
    }
  }
  return version;
}

port = get_http_port( default:8080 );
banner = get_http_banner( port:port );

if( _banner = egrep( pattern:"^Server: (MortBay-)?Jetty", string:banner, icase:TRUE ) ) {

  version   = "unknown";
  installed = TRUE;
  concluded = _banner;

  # Server: Jetty(9.2.14.v20151106)
  # Server: Jetty(6.1.x)
  # Server: Jetty(6.1.3)
  # Server: Jetty(9.2.z-SNAPSHOT)
  # Server: Jetty(winstone-2.8)
  # Server: Jetty(9.4.z-SNAPSHOT)
  # Server: Jetty(8.y.z-SNAPSHOT)
  # Server: MortBay-Jetty-2.2.1
  # Server: MortBay-Jetty-2.2.4
  ver = eregmatch( pattern:"Jetty.([0-9.]+)([a-zA-Z]+[0-9]+)?", string:_banner );
  _ver = jetty_extract_version( ver:ver );
  if( _ver )
    version = _ver;
}

if( ! installed ) {

  # If banner is changed / hidden but default error page still exists.
  url = "/non-existent.html";
  req = http_get( item:url, port:port );
  res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE, fetch404:TRUE );

  # <hr><a href="http://eclipse.org/jetty">Powered by Jetty:// 9.4.10.v20180503</a><hr/>
  # <hr><a href="http://eclipse.org/jetty">Powered by Jetty:// 9.4.z-SNAPSHOT</a><hr/>
  # <hr /><i><small>Powered by Jetty:// 8.y.z-SNAPSHOT</small></i>
  # <small><a href="http://jetty.mortbay.org">Powered by jetty://</a></small></i></p>
  # nb: 404 page sometimes doesn't contain a version so just setting it as "installed" in that case.
  # nb: For older Jetty servers like MortBay-Jetty-2.2.1 we only get a HTTP/1.1 100 Continue from get_http_banner()
  #     but the detection below works based on the response of http_keepalive_send_recv().
  if( res =~ "^HTTP/1\.[01] [1-5].*" && ( res =~ ">Powered by Jetty://" || egrep( pattern:"^Server: (MortBay-)?Jetty", string:res, icase:TRUE ) ) ) {
    installed = TRUE;
    version   = "unknown";
    conclUrl  = report_vuln_url( port:port, url:url, url_only:TRUE );

    ver = eregmatch( pattern:">Powered by Jetty:// ([0-9.]+)([a-zA-Z]+[0-9]+)?[^<]*", string:res );
    if( ! ver )
      ver = eregmatch( pattern:"Jetty.([0-9.]+)([a-zA-Z]+[0-9]+)?", string:res );
    _ver = jetty_extract_version( ver:ver );
    if( _ver ) {
      version = _ver;
      concluded = ver[0];
    }
  }
}

if( installed ) {

  install = port + "/tcp";
  set_kb_item( name:"jetty/detected", value:TRUE );

  # nb: Don't use / add the .z versions or similar in here as it would cause false
  # positives in version based VTs checking for versions like e.g. 9.4.10.20180503
  cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:eclipse:jetty:" );
  if( ! cpe )
    cpe = "cpe:/a:eclipse:jetty";

   register_product( cpe:cpe, location:install, port:port, service:"www" );
   log_message( data:build_detection_report( app:"Jetty Web Server",
                                             version:version,
                                             install:install,
                                             cpe:cpe,
                                             concluded:concluded,
                                             concludedUrl:conclUrl ),
                port:port );
}

exit( 0 );
