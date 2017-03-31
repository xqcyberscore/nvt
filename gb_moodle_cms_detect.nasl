###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_moodle_cms_detect.nasl 2900 2016-03-21 09:59:24Z cfi $
#
# Moodle CMS Version Detection
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
#
# Modified 2009-03-25 Michael Meyer
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
  script_oid("1.3.6.1.4.1.25623.1.0.800239");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 2900 $");
  script_tag(name:"last_modification", value:"$Date: 2016-03-21 10:59:24 +0100 (Mon, 21 Mar 2016) $");
  script_tag(name:"creation_date", value:"2009-03-03 06:56:37 +0100 (Tue, 03 Mar 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Moodle CMS Version Detection");
  script_summary("Set Version of Moodle CMS in KB");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://moodle.org/");

  script_tag(name:"summary", value:"This host is running moodle.
  Moodle is a Course Management System (CMS), also known as a Learning
  Management System (LMS) or a Virtual Learning Environment (VLE). It
  is a Free web application that educators can use to create effective
  online learning sites.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

port = get_http_port( default:80 );

if( ! can_host_php( port:port ) ) exit( 0 );

foreach dir( make_list_unique( "/moodle", cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";

  rcvRes = http_get_cache( item: dir + "/index.php", port:port );

  if( egrep(pattern: "^Set-Cookie: MoodleSession", string:rcvRes ) ||
      egrep(pattern: '<a [^>]*href="http://moodle\\.org/"[^>]*><img [^>]*src="pix/moodlelogo.gif"', string:rcvRes) ) {

    version = "unknown";

    ver = eregmatch( string: rcvRes, pattern: "title=.Moodle ([0-9.]+)\+*.*[(Build: 0-9)]*" );

    if( ! isnull( ver[1] ) ) {
      version = ver[1];
    } else {
      # not really accurate, but better then nothing
      sndReq = http_get( item: dir + "/mod/hotpot/README.TXT", port:port );
      rcvRes = http_keepalive_send_recv( port:port, data:sndReq, bodyonly:TRUE );
 
      ver = eregmatch( string: rcvRes, pattern: "HotPot module for Moodle ([0-9.]+)" );
      if( ! isnull( ver[1] ) ) {
        version = ver[1];
        not_accurate = TRUE;
      }
    }

    if( not_accurate ) {
      extra = 'OpenVAS was not able to extract the exact version number. Further tests on moodle\ncould lead to false positives.';
    }

    tmp_version = version + " under " + install;
    set_kb_item( name:"www/" + port + "/moodle", value:tmp_version );
    set_kb_item( name:"Moodle/Version", value:version );

    ## build cpe and store it as host_detail
    cpe = build_cpe( value: version, exp:"^([0-9.]+)", base:"cpe:/a:moodle:moodle:" );
    if( isnull( cpe ) )
      cpe = 'cpe:/a:moodle:moodle';

    ## Register Product and Build Report
    register_product( cpe:cpe, location:install, port:port );

    log_message( data:build_detection_report( app:"moodle",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              extra:extra,
                                              concluded:ver[0] ),
                                              port:port );
    exit( 0 );
  }
}

exit( 0 );
