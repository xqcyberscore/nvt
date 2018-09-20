###############################################################################
# OpenVAS Vulnerability Test
# $Id: sw_apcu_info.nasl 11453 2018-09-18 11:25:31Z cfischer $
#
# APC / APCu INFO page accessible
#
# Authors:
# Christian Fischer <info@schutzwerk.com>
#
# Copyright:
# Copyright (c) 2015 SCHUTZWERK GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.111025");
  script_version("$Revision: 11453 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-18 13:25:31 +0200 (Tue, 18 Sep 2018) $");
  script_tag(name:"creation_date", value:"2015-07-27 16:00:00 +0200 (Mon, 27 Jul 2015)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("APC / APCu INFO page accessible");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2015 SCHUTZWERK GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Delete them or restrict access to the listened files.");

  script_tag(name:"summary", value:"The APC / APCu INFO page is providing internal information
  about the system.");

  script_tag(name:"impact", value:"Some of the information that could be gathered from this file
  includes: The running APC/APCu version, the PHP version, the webserver version.");

  script_tag(name:"solution_type", value:"Workaround");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

function get_php_version( data ) {

  if( isnull( data ) ) return;

  vers = eregmatch( pattern:'>PHP Version</td><td>([0-9.]+(-[0-9])?).*</td></tr>', string:data );
  if( isnull ( vers[1] ) )
    return;
  else
    return vers[1];
}

files = make_list( "/index.php", "/apc.php", "/apcu.php", "/apcinfo.php" );

port = get_http_port( default:80 );
if( ! can_host_php( port:port ) ) exit( 0 );
#host = http_host_name( dont_add_port:TRUE );

foreach dir( make_list_unique( "/", "/apc", "/cache", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";

  foreach file( files ) {

    url = dir + file;
    res = http_get_cache( item:url, port:port );
    if( ! res ) continue;

    if( res =~ "^HTTP/1\.[01] 200" && ( "<title>APC INFO" >< res || "<title>APCu INFO" >< res ) ) {
      rep += report_vuln_url( port:port, url:url, url_only:TRUE ) + '\n';
      if( ! phpversion ) {
        phpversion = get_php_version( data:res );
      }
    }
  }
}

# TODO: Save the output into a different KB key and update
# gb_php_detect.nasl to use this info as well. Also remove
# the can_host_php() above once this is done as the NVT
# would need to run before gb_php_detect.nasl. Take care
# to not introduce some sort of dependency cyle.
#phpinfoVers = get_kb_list( "php/phpinfo/" + host + "/" + port + "/detected_versions" );
#
#if( ! isnull( phpversion ) && isnull( phpinfoVer ) )
#  set_kb_item( name:"php/phpinfo/" + host + "/" + port + "/detected_versions", value:phpversion );

if( rep ) {
 report = string("The following files are providing a APC / APCu INFO page which disclose potentially sensitive information to the remote attacker : ", rep );
 security_message( port:port, data:report );
 exit( 0 );
}

exit( 99 );