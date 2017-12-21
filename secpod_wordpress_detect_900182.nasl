###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_wordpress_detect_900182.nasl 8197 2017-12-20 12:50:38Z cfischer $
#
# WordPress Version Detection
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2008 SecPod, http://www.secpod.com
#
# Modified to Detect Versions, When it is Under Root folder
#  - By Sharath S <sharaths@secpod.com> On 2009-08-18
#
# Updated By: Thanga Prakash S <tprakash@secpod.com> on 2013-09-04
# According to CR57 and new style script_tags.
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
  script_oid("1.3.6.1.4.1.25623.1.0.900182");
  script_version("$Revision: 8197 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-12-20 13:50:38 +0100 (Wed, 20 Dec 2017) $");
  script_tag(name:"creation_date", value:"2008-12-26 14:23:17 +0100 (Fri, 26 Dec 2008)");
  script_name("WordPress Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 SecPod");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detection of installed version of
  WordPress/WordPress-Mu.

  This script sends HTTP GET request and try to get the version from the
  response, and sets the result in KB.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

## Variable Initialization
flag = "";
port = "";
wpName = "";
wpmuName = "";
checkduplicate = "";

port = get_http_port( default:80 );

if( ! can_host_php( port:port ) ) exit(0);

foreach dir( make_list_unique( "/", "/blog", "/wordpress", "/wordpress-mu", cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";

  foreach file( make_list( "/", "/index.php" ) ) {

    url = dir + file;
    res = http_get_cache( item:url, port:port );

    if( res && "WordPress" >< res && res =~ "HTTP/1.. 200" ) {

      if( "WordPress Mu" >< res ) {
        version = "unknown";
        wpmuVer = eregmatch( pattern:"WordPress ([0-9]\.[0-9.]+)", string:res );
        if( wpmuVer[1] ) version = wpmuVer[1];
        tmp_version = version + " under " + install;
        set_kb_item( name:"www/" + port + "/WordPress-Mu", value:tmp_version );
        set_kb_item( name:"wordpress/installed", value:TRUE );

        ## Check if version is already set
        if (version + ", " >< checkduplicate){
          continue;
        }
        ##Assign detected version value to checkduplicate so as to check in next loop iteration
        checkduplicate  += version + ", ";

        register_and_report_cpe( app:"WordPress-Mu", ver:version, concluded:wpmuVer[0], base:"cpe:/a:wordpress:wordpress_mu:", expr:"^([0-9.]+)", insloc:install, regPort:port );
      }

      if( "WordPress Mu" >!< res ) {

        wpVer = eregmatch( pattern:"WordPress ([0-9]\.[0-9.]+)", string:res );
        if( wpVer[1] ) {
          flag = 1;
          tmp_version = wpVer[1] + " under " + install;
          set_kb_item( name:"www/" + port + "/WordPress", value:tmp_version );
          set_kb_item( name:"wordpress/installed", value:TRUE );

          ## Check if version is already set
          if (wpVer[1] + ", " >< checkduplicate){
            continue;
          }
          ##Assign detected version value to checkduplicate so as to check in next loop iteration
          checkduplicate  += wpVer[1] + ", ";

          register_and_report_cpe( app:"WordPress", ver:wpVer[1], concluded:wpVer[0], base:"cpe:/a:wordpress:wordpress:", expr:"^([0-9.]+)", insloc:install, regPort:port );
        }
      }
    }
  }
}

##Try to get version from README file
if( ! flag ) {

  foreach dir( make_list_unique( "/", "/wordpress", "/blog", cgi_dirs( port:port ) ) ) {

    install = dir;
    if (dir == "/") dir = "";

    url = dir + '/readme.html';
    req = http_get( item:url, port:port );
    res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

    if( res && "WordPress" >< res && res =~ "HTTP/1.. 200" ) {

      wpVer = eregmatch( pattern:"> Version ([0-9.]+)", string:res );
      if( wpVer[1] ) {
        tmp_version = wpVer[1] + " under " + install;
        flag = 1;
        set_kb_item( name:"www/" + port + "/WordPress", value:tmp_version );
        set_kb_item( name:"wordpress/installed", value:TRUE );

        ## Check if version is already set
        if (wpVer[1] + ", " >< checkduplicate){
          continue;
        }
        ##Assign detected version value to checkduplicate so as to check in next loop iteration
        checkduplicate  += wpVer[1] + ", ";

        register_and_report_cpe( app:"WordPress", ver:wpVer[1], concluded:wpVer[0], base:"cpe:/a:wordpress:wordpress:", expr:"^([0-9.]+)", insloc:install, regPort:port );
      }
    }
  }
}

##Try to get version from wp-links-opml.php file
if( ! flag ) {

  rootInstalled = 0;

  foreach dir( make_list_unique( "/", "/wordpress", "/blog", cgi_dirs( port:port ) ) ) {

    if( rootInstalled ) break;

    install = dir;
    if( dir == "/" ) dir = "";

    url = dir + '/wp-links-opml.php';
    req = http_get( item:url, port:port );
    res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

    if( res && '<!-- generator="WordPress' >< res && res =~ "HTTP/1.. 200" ) {
      version = "unknown";
      wpVer = eregmatch( pattern:'<!-- generator="WordPress/([0-9.]+)', string:res );
      if( wpVer[1] ) version = wpVer[1];
      tmp_version = version + " under " + install;
      flag = 1 ;
      if( dir == "" ) rootInstalled = 1;
      set_kb_item( name:"www/" + port + "/WordPress", value:tmp_version );
      set_kb_item( name:"wordpress/installed", value:TRUE );

      ## Check if version is already set
      if (version + ", " >< checkduplicate){
        continue;
      }
      ##Assign detected version value to checkduplicate so as to check in next loop iteration
      checkduplicate  += version + ", ";

      register_and_report_cpe( app:"WordPress", ver:version, concluded:wpVer[0], base:"cpe:/a:wordpress:wordpress:", expr:"^([0-9.]+)", insloc:install, regPort:port );
    }
  }
}

##Try to get version from the /feed/ url
if( ! flag ) {

  rootInstalled = 0;

  foreach dir( make_list_unique( "/", "/wordpress", "/blog", cgi_dirs( port:port ) ) ) {

    if( rootInstalled ) break;

    install = dir;
    if( dir == "/" ) dir = "";

    url = dir + '/feed/';
    req = http_get( item:url, port:port );
    res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

    if( res && "<generator>http://wordpress.org/" >< res && res =~ "HTTP/1.. 200" ) {
      version = "unknown";
      wpVer = eregmatch( pattern:"v=([0-9.]+)</generator>", string:res );
      if( wpVer[1] ) version = wpVer[1];
      tmp_version = version + " under " + install;
      flag = 1 ;
      if( dir == "" ) rootInstalled = 1;
      set_kb_item( name:"www/" + port + "/WordPress", value:tmp_version );
      set_kb_item( name:"wordpress/installed", value:TRUE );

      ## Check if version is already set
      if (version + ", " >< checkduplicate){
        continue;
      }
      ##Assign detected version value to checkduplicate so as to check in next loop iteration
      checkduplicate  += version + ", ";

      register_and_report_cpe( app:"WordPress", ver:version, concluded:wpVer[0], base:"cpe:/a:wordpress:wordpress:", expr:"^([0-9.]+)", insloc:install, regPort:port );
    }
  }
}

if( ! flag ) {

  rootInstalled = 0;

  foreach dir( make_list_unique( "/", "/wordpress", "/blog", cgi_dirs( port:port ) ) ) {

    if( rootInstalled ) break;

    install = dir;
    if( dir == "/" ) dir = "";

    url = dir + '/wp-login.php';
    req = http_get( item:url, port:port );
    res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

    if( res && "wp-includes" >< res && "wp-admin" >< res && res =~ "HTTP/1.. 200" ) {
      version = "unknown";
      wpVer = eregmatch( pattern:"ver=([0-9.]+)", string:res );
      if( wpVer[1] ) version = wpVer[1];
      if( dir == "" ) rootInstalled = 1;
      tmp_version = version + " under " + install;
      set_kb_item( name:"www/" + port + "/WordPress", value:tmp_version );
      set_kb_item( name:"wordpress/installed", value:TRUE);

      ## Check if version is already set
      if (version + ", " >< checkduplicate){
        continue;
      }
      ##Assign detected version value to checkduplicate so as to check in next loop iteration
      checkduplicate  += version + ", ";

      register_and_report_cpe( app:"WordPress", ver:version, concluded:wpVer[0], base:"cpe:/a:wordpress:wordpress:", expr:"^([0-9.]+)", insloc:install, regPort:port );
    }
  }
}

exit( 0 );
