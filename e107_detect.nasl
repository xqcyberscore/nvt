###############################################################################
# OpenVAS Vulnerability Test
# $Id: e107_detect.nasl 5255 2017-02-10 08:56:42Z cfi $
#
# e107 Detection
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100133");
  script_version("$Revision: 5255 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-02-10 09:56:42 +0100 (Fri, 10 Feb 2017) $");
  script_tag(name:"creation_date", value:"2009-04-16 19:20:22 +0200 (Thu, 16 Apr 2009)");
  script_name("e107 Detection");
  script_summary("Checks for the presence of e107");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://e107.org/");

  script_tag(name:"summary", value:"This host is running e107, a content management system written in
  PHP and using the popular open source MySQL database system for content storage.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

port = get_http_port( default:80 );

if( ! can_host_php( port:port ) ) exit( 0 );

foreach dir( make_list_unique( "/e107", "/cms", cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";

  req = http_get( item:dir + "/e107_admin/admin.php", port:port );
  buf = http_keepalive_send_recv( port:port, data:req );
  buf2 = http_get_cache( item:dir + "/news.php", port:port );

  if( egrep( pattern:'This site is powered by <a.*e107.org.*[^>]+>e107</a>', string:buf, icase:TRUE ) || "e107 Powered Website: News" >< buf2 ) {

    version = "unknown";

    ### try to get version. Not possible... TODO
    #version = eregmatch(string: buf, pattern: "",icase:TRUE);

    #if ( !isnull(version[1]) ) {
    #   vers=chomp(version[1]);
    #}

    tmp_version = version + " under " + install;
    set_kb_item( name:"www/" + port + "/e107", value:tmp_version );
    set_kb_item( name:"e107/installed", value:TRUE );

    ## build cpe and store it as host_detail
    cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:e107:e107:" );
    if( isnull( cpe ) )
      cpe = 'cpe:/a:e107:e107';

    register_product( cpe:cpe, location:install, port:port );

    log_message( data:build_detection_report( app:"e107",
                                              version:version,
                                              install:install,
                                              cpe:cpe ),
                                              port:port );
  }
}

exit( 0 );
