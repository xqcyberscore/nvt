###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_discourse_detect.nasl 10795 2018-08-06 14:09:55Z cfischer $
#
# Discourse Detection
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.108454");
  script_version("$Revision: 10795 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-08-06 16:09:55 +0200 (Mon, 06 Aug 2018) $");
  script_tag(name:"creation_date", value:"2018-08-04 23:29:30 +0200 (Sat, 04 Aug 2018)");
  script_name("Discourse Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.discourse.org/");

  script_tag(name:"summary", value:"Detection of Discourse.

  The script sends a connection request to the server and attempts to
  identify an installed Discourse software from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

port = get_http_port( default:80 );

foreach dir( make_list_unique( "/", "/forum", "/forums", "/community", cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";

  buf = http_get_cache( item:dir + "/", port:port );

  if( buf =~ "^HTTP/1\.[01] 200" &&
        ( '<meta name="discourse_theme_key"' >< buf ||
          '<meta name="discourse_theme_id"' >< buf ||
          '<meta name="discourse_current_homepage"' >< buf ||
          '<meta name="generator" content="Discourse' >< buf ||
          '<p>Powered by <a href="https://www.discourse.org">Discourse</a>' >< buf ||
          "<script>Discourse._registerPluginCode" >< buf ||
          "Discourse.start();" >< buf ) ) {

    version = "unknown";
    # CPEs not registered yet
    cpe = "cpe:/a:discourse:discourse";
    set_kb_item( name:"discourse/detected", value:TRUE );

    # <meta name="generator" content="Discourse 2.1.0.beta3 - https://github.com/discourse/discourse version fc3b904e1f64b7d53d7c8f11edd8ef434612f46e">
    # <meta name="generator" content="Discourse 2.0.0.beta9 - https://github.com/discourse/discourse version 7dd68e64d9248f760ded5162448cc8220f429cef">
    # <meta name="generator" content="Discourse 1.9.0.beta3 - https://github.com/discourse/discourse version f1a6449e4be0efe4a11fba75729d9499924b5602">
    vers = eregmatch( string:buf, pattern:'content="Discourse ([0-9.]+)(\\.beta[0-9]+)?' );
    if( vers[1] && vers[2] ) {
      version = vers[1] + vers[2];
      cpe += ":" + version;
    } else if( vers[1] ) {
      version = vers[1];
      cpe += ":" + version;
    }

    register_product( cpe:cpe, location:install, port:port, service:"www" );
    log_message( data:build_detection_report( app:"Discourse",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              concluded:vers[0] ),
                                              port:port );
    # nb: The 404 page "Oops! That page doesn't exist or is private." has the same generator meta name like all other pages
    # so exit here for the case where the web server is e.g. throwing a 200 for non existent pages.
    exit( 0 );
  }
}

exit( 0 );
