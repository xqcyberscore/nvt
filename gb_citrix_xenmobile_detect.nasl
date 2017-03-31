###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_citrix_xenmobile_detect.nasl 3176 2016-04-27 07:21:55Z mime $
#
# Citrix XenMobile Server Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.105569");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version ("$Revision: 3176 $");
 script_tag(name:"last_modification", value:"$Date: 2016-04-27 09:21:55 +0200 (Wed, 27 Apr 2016) $");
 script_tag(name:"creation_date", value:"2016-03-15 18:31:10 +0100 (Tue, 15 Mar 2016)");
 script_name("Citrix XenMobile Server Detection");

 script_tag(name: "summary" , value: "The script sends a connection request to the server and attempts to extract the version number from the reply. When HTTP credentials are given, this script logis in into the XenMobile Server to get installed patch releases.");

 script_tag(name:"qod_type", value:"remote_banner");

 script_summary("Checks for the presence of Citrix XenMobile Server");
 script_category(ACT_GATHER_INFO);
 script_family("Product detection");
 script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80, 443, 8443 );
 script_exclude_keys("Settings/disable_cgi_scanning");

 script_add_preference(name:"XenMobile Username: ", value:"", type:"entry");
 script_add_preference(name:"XenMobile Password: ", type:"password", value:"");

 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("version_func.inc");

port = get_http_port( default:4443 );

url = '/zdm/login_xdm_uc.jsp';
req = http_get( item:url, port:port );
buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( "<title>XenMobile" >!< buf || "Citrix Systems" >!< buf ) exit( 0 );

cpe = 'cpe:/a:citrix:xenmobile_server';
replace_kb_item( name:"citrix_xenmobile_server/installed", value:TRUE );

co = eregmatch( pattern:'Set-Cookie: ([^\r\n]+)', string:buf );

if( ! isnull( co[1] ) )
{
  cookie = co[1];
  host = http_host_name( port:port );

  req = 'GET /controlpoint/rest/xdmServices/general/version HTTP/1.1\r\n' +
        'Host: ' + host + '\r\n' +
        'User-Agent: ' + OPENVAS_HTTP_USER_AGENT + '\r\n' + 
        'Cookie: ' + cookie + '\r\n' +
        'Referer: https://' + host + '/index_uc.html\r\n' +
        'X-Requested-With: XMLHttpRequest\r\n' +
        'Accept-Encoding: identify\r\n' + 
        'Content-Type: application/json; charset=UTF-8\r\n' +
        '\r\n';

  buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

  if( buf =~ 'HTTP/1.. 200' && "<message>" >< buf )
  {
    status = eregmatch( pattern:'<status>([^<]+)</status>', string: buf );
    if( status[1] == 0 )
    {
      version = eregmatch( pattern:'<message>([^<]+)</message>', string:buf );
      if( ! isnull( version[1] ) )
      {
        vers = version[1];
        cpe += ':' + vers;
        replace_kb_item( name:"citrix_xenmobile_server/version", value:vers );
      }
    }
  }
}

register_product( cpe:cpe, location:'/', port:port );

user = script_get_preference( "XenMobile Username: " );
pass = script_get_preference( "XenMobile Password: " );

if( user && pass )
{
  login_credentials = TRUE;
  host = http_host_name( port:port );

  data = 'login=' + user + '&password=' + pass;
  len = strlen( data );

  req = 'POST /zdm/cxf/login HTTP/1.1\r\n' + 
        'Host: ' + host + '\r\n' + 
        'User-Agent: ' + OPENVAS_HTTP_USER_AGENT + '\r\n' +
        'Accept: application/json, text/javascript, */*; q=0.01\r\n' +
        'Accept-Language: en-US,en;q=0.5\r\n' + 
        'Accept-Encoding: identity\r\n' + 
        'DNT: 1\r\n' + 
        'Content-Type: application/x-www-form-urlencoded; charset=UTF-8\r\n' + 
        'X-Requested-With: XMLHttpRequest\r\n' +
        'Referer: https://' + host + '/zdm/login_xdm_uc.jsp\r\n' +
        'Content-Length: ' + len + '\r\n';

  if( ! isnull( co[1] ) )
        req += 'Cookie: ' + co[1] + '\r\n';

  req += 'Connection: keep-alive\r\n' + 
         '\r\n' + 
         data;

  buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

  if( '"status":"OK"' >< buf )
  {
    co = eregmatch( pattern:'Set-Cookie: ([^\r\n]+)', string:buf );
    if( ! isnull( co[1] ) )
    {
      cookie = co[1];

      req = 'GET /controlpoint/rest/releasemgmt/allupdates HTTP/1.1\r\n' +
            'Host: ' + host + '\r\n' +
            'User-Agent: ' + OPENVAS_HTTP_USER_AGENT + '\r\n' +
            'Cookie: ' + cookie + '\r\n' +
            'Referer: https://' + host + '/index_uc.html\r\n' +
            'X-Requested-With: XMLHttpRequest\r\n' +
            'Accept-Encoding: identify\r\n' +
            'Content-Type: application/json; charset=UTF-8\r\n' +
           '\r\n';

      buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );
      if( '"message":"Success"' >< buf )
      {
        login_success = TRUE;

        values = split( buf, sep:",", keep:FALSE );

        foreach val ( values )
          if( "release" >< val )
          {
            rv = eregmatch( pattern:'"release":"([0-9]+[^"]+)"', string:val );

            if( ! isnull( rv[1] ) )
              if( ! hv )
                hv = rv[1];
              else
                if( version_is_greater( version:rv[1], test_version:hv ) ) hv = rv[1];
          }
        }
    }
  }
}


report = 'Detected Citrix XenMobile Server\n' +
         'Version:  ' + vers + '\n' +
         'CPE:      ' + cpe + '\n' + 
         'Location: /';

if( login_credentials )
{
  if( ! login_success )
    report += '\n\nIt was not possible to login into the remote Citrix XenMobile Server using the supplied HTTP credentials\n';
  else
    report += '\n\nIt was possible to login into the remote Citrix XenMobile Server using the supplied HTTP credentials\n';
}

if( hv )
{
  report += '\nHighest installed patch release: ' + hv + '\n';
  replace_kb_item( name:"citrix_xenmobile_server/patch_release", value:hv );
}
else
  if( login_credentials )
  {
    report += '\nNo patches installed\n';
    replace_kb_item( name:"citrix_xenmobile_server/patch_release", value:'no_patches' );
  }
  else
    report += '\n\nNo HTTP(s) credentials where given. Scanner was not able to to extract patch information from the application.\n';

log_message( port:port, data:report );

exit( 0 );

