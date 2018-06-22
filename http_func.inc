###############################################################################
# OpenVAS Include File
# $Id: http_func.inc 10283 2018-06-21 11:10:20Z cfischer $
#
# Methods to handle HTTP
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
# get_http_port added by Georges Dagousset
#
# Copyright:
# Copyright (C) 2002 Michel Arboi <arboi@alussinan.org>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#
# $Revision: 10283 $
#
###############################################################################

global_var OPENVAS_HTTP_USER_AGENT;

if ( ! OPENVAS_HTTP_USER_AGENT = get_kb_item( "http/user-agent" ) )
  OPENVAS_HTTP_USER_AGENT = 'Mozilla/5.0 [en] (X11, U; OpenVAS ' + OPENVAS_VERSION + ')';

# Enables debugging output for a few functions below
global_var _http_debug;
_http_debug = FALSE;

# global vars passed to e.g. http_keepalive.inc
global_var http_cgi_disabled, optimize_test_enabled;
http_cgi_disabled     = get_kb_item( "Settings/disable_cgi_scanning" );
optimize_test_enabled = get_preference( "optimize_test" );

# Global keys to avoid that we're repeatedly asking redis for something we already know
global_var _http_is_broken_array;
# nb: key is the port or NULL (if not previously checked, value TRUE/FALSE if broken or not
_http_is_broken_array = make_array();

function headers_split( h ) {

  local_var ret, array, item, subarray, end;

  if( ! h ) set_kb_item( name: "nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#h#-#headers_split" );

  end = strstr( h, '\r\n\r\n' );
  if( end ) h -= end;

  array = split( h, keep:FALSE );
  foreach item( array ) {
    subarray = split( item, sep:':', keep:FALSE );
    ret[tolower( subarray[0] )] = ereg_replace( pattern:"^ *", replace:"", string:subarray[1] );
  }
  return ret;
}

#
# That's for chunk-decoding
#
function __hex_value( num ) {

  if( num == "a") return( 10 );
  if( num == "b") return( 11 );
  if( num == "c") return( 12 );
  if( num == "d") return( 13 );
  if( num == "e") return( 14 );
  if( num == "f") return( 15 );
  return( int( num ) );
}

function hex2dec( xvalue ) {

  local_var ret, l, i, n, m;

  if( ! xvalue ) {
    set_kb_item( name: "nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#xvalue#-#hex2dec" );
    return(0);
  }

  xvalue = tolower( xvalue );
  if( '\r\n' >< xvalue ) {
    l = strlen( xvalue ) - 2;
  } else if( '\n' >< xvalue ) {
    l = strlen( xvalue ) - 1;
  } else {
    l = strlen( xvalue );
  }

  ret = 0;
  m = 1;
  if( l == 0 ) return 0;

  # Remove the trailing spaces
  while( xvalue[l - 1] == " " && l > 0 ) l--;

  for( i = l; i > 0; i-- ) {
    n = __hex_value( num:xvalue[i - 1] ) * m;
    ret = ret + n;
    m = m * 16;
  }
  return int( ret );
}

# @brief This function creates a HTTP GET request for "/" or a specific URL,
#        sends the request to the target, receives the response and extracts
#        the HTTP header (banner) without the body from the response.
#        If a header was received it is saved into the knowledge base.
#        If a header was requested which was requested previously the cached
#        header will be returned instead of doing a new request.
#
# @param port          the HTTP port of the target
# @param file          the URL/file to request, defaults to "/"
# @param ignore_broken returns the banner even if the remote host was known to be "broken"
#
# @return the header of the remote host or NULL if no response was received, no port parameter was passed or the remote port wasn't scanned
#
function get_http_banner( port, file, ignore_broken ) {

  local_var port, file, ignore_broken;
  local_var soc, sb, banner, req, body;

  if( ! port ) {
    set_kb_item( name: "nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#get_http_banner" );
    return NULL;
  }

  if( ! get_port_state( port ) ) return NULL;

  if( ! file ) file = "/";
  sb = strcat( "www/real_banner/", port, file );
  banner = get_kb_item( sb );
  if( banner ) return banner;

  sb = strcat( "www/banner/", port, file );
  banner = get_kb_item( sb );
  if( banner ) return banner;

  if( ! ignore_broken )
    if( http_is_marked_broken( port:port ) ) return NULL; # TBD: Really return NULL if marked as broken? We still could use the banner version in NVTs...

  # nb: Always keep http_get() before http_open_socket() as the first could
  # fork with multiple vhosts and the childs would share the same socket
  # causing race conditions and similar.
  req = http_get( item:file, port:port );
  soc = http_open_socket( port );
  if( ! soc ) return NULL;

  send( socket:soc, data:req );
  banner = http_recv_headers2( socket:soc );
  #body = http_recv_body( socket:soc, headers:banner ); # TBD: What's the purpose of this?
  http_close_socket( soc );

  if( banner ) replace_kb_item( name:sb, value:banner );
  return banner;
}

# @brief This function returns all HTTP ports of the target system which
#        are saved in the KB entry "Services/www" found by the scanner.
#        If no ports where found open it will exit. In the case if the
#        "unscanned_closed" scanner setting is set to "no" it will return
#        the port passed via the default parameter.
#
# @param default             the port to return if "unscanned_closed" is set to "no" and no ports have been found open
# @param ignore_broken       returns the ports even if they are known to be "broken"
# @param ignore_cgi_disabled returns the ports even if CGI scanning is disabled
#
# @return the open / found HTTP ports or the port passed via the default parameter in the case of no found ports and "unscanned_closed" is set to "no"
#
function get_http_port( default, ignore_broken, ignore_cgi_disabled ) {

  local_var default, port, p, ignore_broken, ignore_cgi_disabled;
  # nb: http_cgi_disabled and optimize_test_enabled are global vars

  if( ! default ) set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#default#-#get_http_port" );

  port = get_kb_item( "Services/www" );
  if( port ) default = port;

  # Includes e.g. PJL ports which are printing everything
  # sent to them so exit for such a port here
  if( http_is_fragile_port( port:default ) ) exit( 0 );

  if( ! ignore_cgi_disabled ) {
    if( http_cgi_disabled ) {
      if( optimize_test_enabled && "yes" >< optimize_test_enabled ) {
        set_kb_item( name:"nvt_cgi_scanning_disabled/" + get_script_oid(), value:get_script_oid() + "#-#get_http_port" );
      }
      exit( 0 );
    }
  }

  if( ! ignore_broken ) {
    p = http_is_marked_broken( port:default );
    if( p ) exit( 0 );
  }

  p = get_kb_item( "Services/www/" + default + "/working" );
  if( p ) return default;

  if( ! get_port_state( default ) ) exit( 0 );

  return default;
}

# (C) Georges Dagousset
# Usage:
# banner = get_http_banner( port:port );
# if( php_ver_match( banner:banner,
#     pattern:".*PHP/((3.*)|(4\.0.*)|(4\.1\.[01].*))"))
#       security_message( port );
#

function php_ver_match( banner, pattern ) {

  local_var line;

  if( ! banner ) set_kb_item( name: "nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#banner#-#php_ver_match" );
  if( ! pattern ) set_kb_item( name: "nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#pattern#-#php_ver_match" );

  line = egrep( pattern:"^Server:.*", string:banner, icase:TRUE );

  if( ereg( pattern:pattern, string:line, icase:TRUE ) ) {
    return( 1 );
  } else {
    line = egrep( pattern:"^X-Powered-By:.*", string:banner, icase:TRUE );
    if( ereg( pattern:pattern, string:line, icase:TRUE ) ) {
      return( 1 );
    }
  }
  return( 0 );
}

# @brief This function checks if the remote web server is responding
#        to an HTTP GET request.
#
# @param port  the port of the remote server to check
# @param retry the amount of retries until the check is considered as failed.
#              This parameter is optional and defaults to 2 retries and is
#              limited to a max. of 5 retries.
#
# @return TRUE if the remote web server is not responding, FALSE otherwise
#
function http_is_dead( port, retry ) {

  local_var port, retry, i, soc, url, req, code, h, h2, b;

  if( ! port ) {
    set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#http_is_dead" );
    return FALSE;
  }

  if( ! retry )   retry = 2;
  if( retry > 5 ) retry = 5; # nb: Limit the amount of retries to a sane default

  # nb: http_head does not work against SWAT & VNC (& probably others...)
  # nb: Always keep http_get() before http_open_socket() as the first could
  # fork with multiple vhosts and the childs would share the same socket
  # causing race conditions and similar.
  url = strcat( "/OpenVASTest", rand(), ".html" );
  req = http_get( item:url, port:port );

  i = 0;
  soc = http_open_socket( port );
  while( ! soc && i++ < retry ) {
    sleep( i );
    soc = http_open_socket( port );
    if( _http_debug ) display( "DEBUG: i = ", i, "\n" );
  }
  if( ! soc ) return TRUE;

  send( socket:soc, data:req );
  code = recv_line( socket:soc, length:1024 );
  if( code ) {
    h = http_recv_headers2( socket:soc );
    h2 = strcat( code, h );
    b = http_recv_body( socket:soc, headers:h2 );
  }
  http_close_socket( soc );
  if( ! code ) return TRUE;

  # 500: internal server error
  # 501: not implemented = unsupported method...
  # 502: Bad gateway = upstream server sends an invalid response
  # 503: service unavailable = temporary overloading...
  # 504: gateway timeout = no timely response from upstream server
  if( ereg( pattern:"^HTTP/1\.[01] +50[234]", string:code ) ) return TRUE;

  return FALSE;
}

# @brief This function requests a specified URL and checks the response if it
#        is containing pattern for windows related files (autoexec.bat, win.ini
#        and boot.ini).
#
# @param port        the port of the remote server to check
# @param url         the URL to check
# @param quickcheck  if set to TRUE the response is only checked for an existing HTTP 200 status code
#
# @return TRUE if the remote web server has responded with the expected pattern, FALSE otherwise and
#              NULL in the case where no connection to the target could be established or not all
#              required parameters where passed.
#
function do_check_win_dir_trav( port, url, quickcheck ) {

  local_var port, url, quickcheck;
  local_var soc, req, cod, buf;

  if( ! port ) {
    set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#do_check_win_dir_trav" );
    return NULL;
  }
  if( ! url ) {
    set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#url#-#do_check_win_dir_trav" );
    return NULL;
  }

  if( _http_debug ) display( "DEBUG: check_win_dir_trav(port=", port, ", url=", url, ", quickcheck=", quickcheck, ")\n" );

  # nb: Always keep http_get() before http_open_socket() as the first could
  # fork with multiple vhosts and the childs would share the same socket
  # causing race conditions and similar.
  req = http_get( item:url, port:port );
  soc = http_open_socket( port );
  if( ! soc ) {
    if( _http_debug ) display( "DEBUG: check_win_dir_trav: cannot open socket to ", port, "\n" );
    return NULL;
  }

  send( socket:soc, data:req );
  cod = recv_line( socket:soc, length:80 );
  buf = http_recv( socket:soc, code:cod );
  http_close_socket( soc );

  if( "content-encoding: gzip" >< tolower( buf ) )
    buf = http_gunzip( buf:buf );

  if( quickcheck ) {
    if( " 200 " >< cod ) return TRUE;
    return FALSE;
  }

  if( "; for 16-bit app support" >< buf || "[boot loader]" >< buf ) {
    return TRUE;
  }
  return FALSE;
}

# @brief This function requests a specified URL and checks the response if it
#        is containing pattern for windows related files (autoexec.bat, win.ini
#        and boot.ini). It is an extension to the do_check_win_dir_trav function
#        and is additionally checking if the web server is responding with the
#        expected pattern on a non-existent random file.
#
# @param port        the port of the remote server to check
# @param url         the URL to check
# @param quickcheck  if set to TRUE the response is only checked for an existing HTTP 200 status code
#
# @return TRUE if the remote web server has responded with the expected pattern, FALSE otherwise and
#              NULL in the case where no connection to the target could be established, not all
#              required parameters where passed or if the web server is responding with the expected
#              pattern on a non-existent random file.
#
function check_win_dir_trav( port, url, quickcheck ) {
  local_var port, url, quickcheck;
  if( do_check_win_dir_trav( port:port, url:url + rand(), quickcheck:quickcheck ) )
    return NULL;
  else
    return do_check_win_dir_trav( port:port, url:url, quickcheck:quickcheck );
}

function http_recv_headers2( socket ) {

  local_var buf, line, counter;

  if( ! socket ) set_kb_item( name: "nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#socket#-#http_recv_headers2" );

  while( TRUE ) {
    counter ++;
    line = recv_line( socket:socket, length:4096 );
    buf += line;
    if( line == '\r\n' ) break;
    if( ! strlen( line ) ) break;
    if( strlen( line ) == 1 && line =~ '^\x0a$' ) break;
    if( counter > 1024 ) break;
  }

  return buf;
}

# This function does not return the headers!
# So 'length' parameter does not include headers length, even if we
# have to read them.
# If Content-length is set, "length" only allows the function to read
# more data, if available. i.e., it is ignored most of the time.
#

function http_recv_body( socket, headers, length ) {

  local_var h, cl, l, min, max, x, n, to, gzip;

  if( ! socket ) set_kb_item( name: "nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#socket#-#http_recv_body" );

  if( ! headers ) {
    h = http_recv_headers2( socket:socket );
  } else {
    h = headers;
  }

  l = -1;
  cl = egrep( pattern:"^Content-length: *[0-9]+", string:h, icase:TRUE );
  if( "content-encoding: gzip" >< tolower( h ) ) gzip = TRUE;

  if( cl ) {
    l = int( ereg_replace( pattern:"Content-length: *([0-9]+).*", replace:"\1", string:cl, icase:TRUE ) );
  }
  # "l" = Content-Length or -1 now

  max = -1;
  min = -1;

  if( l < 0 && egrep( pattern:"^transfer-encoding: chunked", string:h, icase:TRUE ) ) {

    local_var tmp, body;
    body = "";

    while( 1 ) {
      tmp = recv_line( socket:socket, length:4096 );
      l = hex2dec( xvalue:tmp );
      body = strcat( body, recv( socket:socket, length:l, min:l ) );
      # "\r\n"
      recv( socket:socket, length:2, min:2 );
      if( l == 0 ) {
        return( body ); # This is expected - don't put this line before the previous
      }
    }
  }

  if( length ) max = length;
  if( l >= 0 ) min = int( l );
  if( l >= max || min >= max ) max = l;
  if( max < 0 ) {
    if( _http_debug ) display( "DEBUG: http_recv_body: bogus or no Content-length field, and no 'length' parameter set! Defaulting to 32 KB\n" );
    max = 32768;
  }
  if( _http_debug ) display( "DEBUG: http_recv_body: min=", min, "; max=", max, "\n" );
  if( min > 0 ) {
    x = recv( socket:socket, length:max, min:min );
  } else {
    n = recv( socket:socket, min:max, length:max );
    x = n;
    while( strlen( n ) >= max && max != 0 ) {
      n = recv( socket:socket, length:max );
      x += n;
      if( strlen( x ) > 1048576 ) {
        if( _http_debug ) display( "DEBUG: http_recv_body: read stopped after 1 MB!\n" );
        break;
      }
    }
  }

  if( gzip ) return http_gunzip( buf:x, onlybody:FALSE );

  return( x );
}

# This function reads everything
# Note that bodylength will be ignored if the Content-length field is set

function http_recv( socket, code ) {

  local_var h, b, l;

  if( ! socket ) set_kb_item( name: "nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#socket#-#http_recv" );

  if( code ) {
    h = strcat( code ); # Convert to string, just in case
    repeat
    {
      l = recv_line( socket:socket, length:2048 );
      h = h + l;
    }
    until( ! l || l =~ '^[\r\n]+$' ); # EOF or empty line
    if( ! l ) return h;
  } else {
    h = http_recv_headers2( socket:socket );
    if( ! h ) return( NULL );
    else if( ! ereg( pattern:"^HTTP/.* [0-9]*", string:h ) ) return h;
    h = strcat( h, '\r\n' );
  }
  b = http_recv_body( socket:socket, headers:h, length:0 );
  return strcat( h, b );
}

function http_recv_length( socket, bodylength ) {

  local_var h, b;

  if( ! socket ) set_kb_item( name: "nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#socket#-#http_recv_length" );
  if( ! bodylength ) set_kb_item( name: "nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#bodylength#-#http_recv_length" );

  h = http_recv_headers2( socket:socket );
  b = http_recv_body( socket:socket, headers:h, length:bodylength );
  return strcat( h, '\r\n', b );
}

function http_send_recv( port, data ) {

  local_var s, r;

  if( ! port ) set_kb_item( name: "nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#http_send_recv" );
  if( ! data ) set_kb_item( name: "nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#data#-#http_send_recv" );

  s = http_open_socket( port );
  if( ! s ) return;
  send( socket:s, data:data );
  while( x = http_recv( socket:s ) ) {
    if( "content-length: " >< tolower( x ) && "206 Partial" >!< x ) {
      cl = eregmatch( pattern:"Content-Length: ([0-9]+)", string:x, icase:TRUE );
      if( ! isnull( cl[1] ) ) conlen = int( cl[1] );
    }

    r += x;
    if( ( conlen  && conlen > 0 ) && strlen( r ) >= conlen ) break;

  }

  http_close_socket( s );

  if( "content-encoding: gzip" >< tolower( r ) )
    return http_gunzip( buf:r );

  return r;

}

function cgi_dirs( port ) {

  local_var port, kb, optimize, usercgis;
  # nb: http_cgi_disabled and optimize_test_enabled are global vars

  if( ! port ) set_kb_item( name: "nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#cgi_dirs" );

  if( http_cgi_disabled ) {
    if( optimize_test_enabled && "yes" >< optimize_test_enabled ) {
      set_kb_item( name:"nvt_cgi_scanning_disabled/" + get_script_oid(), value:get_script_oid() + "#-#cgi_dirs()" );
    }
    #return NULL; # Old behaviour
    exit( 0 ); # Throws a "nasl_array_iterator: unhandled type 57" message if cgi_dirs() is called within a foreach but not within a make_list()
  }

  if( port ) {
    kb = get_kb_list( "www/" + port + "/content/directories" );
  } else {
    kb = get_kb_list( "www/*/content/directories" );
  }

  usercgis = get_kb_list( "/user/cgis" );
  if( isnull( usercgis ) ) usercgis = "/";
  if( isnull( kb ) ) {
    kb = make_list( usercgis, "/" );
  } else {
    kb = make_list( usercgis, kb, "/" );
  }

  return( make_list_unique( kb ) );
}

function can_host_php( port ) {

  local_var port, banner, files, srv_pattern;

  if( ! port ) {
    set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#can_host_php" );
    return;
  }

  if( get_kb_item( "www/" + port + "/PHP" ) ) return TRUE;

  files = get_kb_list( "www/" + port + "/content/extensions/php*" );
  if( ! isnull( files ) ) return TRUE; # Hosting .php* files

  if( get_kb_item( "greenbone/gos/http/" + port + "/detected" ) ) return FALSE;
  if( get_kb_item( "gsa_or_gsa_ng/" + port + "/detected" ) ) return FALSE;

  banner = get_http_banner( port:port );
  if( ! banner ) {
    return FALSE; # Broken Web Server
  } else {

    banner = tolower( banner );

    if( banner =~ 'powered.*php' ||
        banner =~ "server.*php.*" ||
        banner =~ "^set-cookie:.*phpsessid" ||
        "content-type: application/x-appweb-php" >< banner )
      return TRUE;

    # TODO: Find more possible web server to add
    srv_pattern  = "(apache|nginx|thttpd|aolserver|pi3web|zeus|iis|icewarp|lighttpd|";
    srv_pattern += "hiawatha|litespeed|caddy|panweb|embedthis-http|embedthis-appweb|mbedthis-appweb)";

    if( egrep( pattern:"^Server:.*" + srv_pattern, string:banner, icase:TRUE ) ) {
      return TRUE;
    }
  }

  if( egrep( pattern:"^Server:.*", string:banner, icase:TRUE ) ) {
    return FALSE; # Unknown web server, should be added above if we know that it can host a PHP website
  } else {
    if( "user-agent: loolwsd wopi" >< banner || "x-powered-by: express" >< banner ) {
      return FALSE; # We know that this can't host a PHP website
    } else {
      return TRUE; # Server: banner hidden - might be able to host a PHP website
    }
  }
}

function can_host_asp( port ) {

  local_var port, banner, files, srv_pattern;

  if( ! port ) {
    set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#can_host_asp" );
    return;
  }

  files = get_kb_list( "www/" + port + "/content/extensions/asp*" );
  if( ! isnull( files ) ) return TRUE; # Hosting .asp / .aspx files

  if( get_kb_item( "greenbone/gos/http/" + port + "/detected" ) ) return FALSE;
  if( get_kb_item( "gsa_or_gsa_ng/" + port + "/detected" ) ) return FALSE;

  banner = get_http_banner( port:port );
  if( ! banner ) {
    return FALSE; # Broken Web Server
  } else {

    banner = tolower( banner );

    if( banner =~ 'powered.*asp' ||
        banner =~ "server.*asp.*" ||
        banner =~ "^set-cookie:.*asp\.net_sessionid" ||
        banner =~ "^set-cookie:.*aspsessionid" ||
        "x-aspnet-version" >< banner )
      return TRUE;

    srv_pattern = "(iis|goahead-webs)"; # TODO: Find more possible web server to add

    if( egrep( pattern:"^Server:.*" + srv_pattern, string:banner, icase:TRUE ) ) {
      return TRUE;
    }
  }

  if( egrep( pattern:"^Server:.*", string:banner, icase:TRUE ) ) {
    return FALSE; # Unknown web server, should be added above if we know that it can host a ASP/ASP.NET website
  } else {
    if( "user-agent: loolwsd wopi" >< banner || "x-powered-by: express" >< banner ) {
      return FALSE; # We know that this can't host a ASP/ASP.NET website
    } else {
      return TRUE; # Server: banner hidden - might be able to host a ASP/ASP.NET website
    }
  }
}

function http_40x( port, code ) {

  local_var no404;

  if( ! port ) set_kb_item( name: "nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#http_40x" );
  if( ! code ) set_kb_item( name: "nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#code#-#http_40x" );

  if( ereg( string:code, pattern:"^HTTP/1\.[01] +40[0-9]" ) )
    return TRUE;

  no404 = get_kb_item( "www/no404/" + port );
  if( no404 && no404 >< code )
    return TRUE;
  return FALSE;
}

function http_gunzip( buf, onlybody ) {

  local_var onlybody, lines, line, sep, header, body, h, tmpdir, tmpfile, tmpfile_gz, res;

  if( ! buf ) {
    set_kb_item( name: "nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#buf#-#http_gunzip" );
    return FALSE;
  }

  if( "##**##UNZIPPED##**##" >< buf ) return buf;

  if( "content-encoding: gzip" >!< tolower( buf ) && ! onlybody ) return buf;

  if( ! onlybody ) {

    lines = split( buf, keep:FALSE );

    foreach line( lines ) {

      if( ! sep && line !~ "^$" )
        header += line + '\n';

      if( line =~ "^$" && ! body ) {
        sep = TRUE;
        continue;
      }

      if( sep )
        body += line + '\n';
    }
  } else {
    body = buf;
  }

  if( ! body ) return buf;

  if( defined_func( "gunzip" ) ) {

    if( body = gunzip( data:body ) ) {

      if( onlybody ) return body + '\n\n\n##**##UNZIPPED##**##';

      h = ereg_replace( string:header, pattern:'(content-encoding:[^\r\n]+[\r\n]+)', replace:"", icase:TRUE );
      return( h + '\r\n\r\n' + body + '\n\n\n##**##UNZIPPED##**##' );
    }
    return buf;
  } else {

    if( ! find_in_path( "gunzip" ) ) return buf;

    tmpdir = get_tmp_dir();
    if( ! tmpdir ) return buf;

    file = "openvas_" + rand();
    tmpfile = tmpdir + file;
    tmpfile_gz = tmpfile + '.gz';

    if( ! fwrite( data:body + '\r\n', file:tmpfile_gz ) ) return buf;

    argv[i++] ="gunzip";
    argv[i++] = tmpfile_gz;

    res = pread( cmd:"gunzip", argv:argv, cd:0 );

    if( file_stat( tmpfile_gz ) ) unlink( tmpfile_gz );

    if( file_stat( tmpfile ) ) {

      res = fread( tmpfile );
      unlink( tmpfile );

      if( ! res ) return buf;

      if( onlybody ) return res + '\n\n\n##**##UNZIPPED##**##';

      h = ereg_replace( string:header, pattern:'(content-encoding:[^\r\n]+[\r\n]+)', replace:"", icase:TRUE );
      return h + '\r\n\r\n' + res  + '\n\n\n##**##UNZIPPED##**##';
    }
  }
  return buf;
}

function http_host_name( port, use_ip ) {

  local_var port, use_ip, host;

  if( ! port ) set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#http_host_name" );

  if( use_ip ) {
    host = get_host_ip();
  } else {
    host = get_host_name();
  }

  if( port ) {
    if( port != 80 && port != 443 )
      host += ':' + port;
  }
  return host;
}

function make_list_unique( ) {

  local_var ret, args, x, z, a, e;

  ret = make_list();
  args = make_list();

  foreach x( _FCT_ANON_ARGS ) {
    if( typeof( x ) == "array" ) { # e.g. return value from cgi_dirs()
      foreach z( x )
        args = make_list( args, z );
    } else {
      args = make_list( args, x );
    }
  }

  foreach a( args ) {

    e = FALSE;
    foreach r ( ret ) {
      if( a == r ) {
        e = TRUE; # entry already exist
        break;
      }
    }

    if( ! e ) ret = make_list( ret, a ); # entry didn't exist, add entry...
  }
  return ret;
}

# Duplicated from misc_func.inc
function http_is_fragile_port( port ) {

  local_var port, fragile_ports, fragile_port;

  if( ! port ) {
    set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#http_is_fragile_port" );
    return;
  }

  fragile_ports = get_kb_list( "Services/fragile_port" );
  if( ! fragile_ports ) return;

  foreach fragile_port( fragile_ports ) {
    if( port == fragile_port ) return TRUE;
  }

  return;
}

# This function extract the url part of a "Location:" header from a 301/302 redirect response
# It makes also sure that the redirect is not pointing to a different server
#
# Examples are e.g.:
# Location: https://example.com/foo (pointing to the same host)
# Location: http://example.com/foo (pointing to the same host)
# Location: //example.com/foo (pointing to the same host)
# Location: https://example.com/foo (pointing to a different host -> this needs to be ignored)
# Location: http://example.com/foo (to a different host -> this needs to be ignored)
# Location: //example.com/foo (to a different host -> this needs to be ignored)
# Location: /foo
#
# TBD: What to do if a redirect is pointing from e.g. 80 to 443?
#

function extract_location_from_redirect( port, data, debug ) {

  local_var port, data, debug, host, ip, location, location_host, loc;

  if( ! port ) {
    set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#extract_location_from_redirect" );
    return;
  }

  if( ! data ) {
    set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#data#-#extract_location_from_redirect" );
    return;
  }

  host = http_host_name( port:port );
  ip = get_host_ip();

  # Exit if we don't have a location header in the data
  location = egrep( string:data, pattern:"^Location: ", icase:TRUE );
  if( ! location ) return;

  if( debug || _http_debug ) display( 'DEBUG: Location header is: "' + location + '"\n' );

  # Grab everything after Location:
  location -= string( "\r\n" );
  location = ereg_replace( string:location, pattern:"Location: (.*)$", replace:"\1", icase:TRUE );

  if( debug || _http_debug ) display( 'DEBUG: Location header after cleanup is: "' + location + '"\n' );

  # Handle "https://", "http://" and "//" links in the location header
  if( location =~ "^(https:|http:)?//" ) {

    location_host = ereg_replace( string:location, pattern:"(https:|http:)?//([^/]*)/.*", replace:"\2", icase:TRUE );

    if( debug || _http_debug ) display( 'DEBUG: Location header is pointing to host/ip: "' + location_host + '"\n' );

    # The location header is pointing to the same hostname / ip
    if( host >< location_host || ip >< location_host ) {
      loc = ereg_replace( string:location, pattern:"(https:|http:)?//[^/]*/([^?]*)", replace:"/\2", icase:TRUE );
      if( debug || _http_debug ) display( 'DEBUG: Location header is pointing to "' + location + '" on the same host/ip. Returning this location.\n' );
      return loc;
    # If its not pointing to the same hostname / ip we can't follow it
    } else {
      if( debug || _http_debug ) display( 'DEBUG: Location header is pointing to "' + location + '" NOT on the same host/ip. NOT returning this location.\n' );
      return;
    }
  # Handle redirects like "Location: /foo"
  } else {
    if( debug || _http_debug ) display( 'DEBUG: Location header is pointing to "' + location + '" on the same host/ip. Returning this location.\n' );
    return location;
  }
}

function get_cookie_from_header( buf, pattern )
{
  local_var buf, pattern, match;

  if( ! buf ) {
    set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#buf#-#get_cookie_from_header" );
    return;
  }

  if( ! pattern )
    pattern = 'Set-Cookie: ([^\r\n]+)';

  if( match = eregmatch( pattern:pattern, string:buf ) )
    return match[ max_index( match ) -1 ];
}

function create_exploit_req( cgiArray, ex ) {

  local_var cgiArray, ex, pseudocount, rrayval, tmpf, data, param, z, url, i, urls;

  urls = make_array();

  pseudocount = 0;
  foreach rrayval( cgiArray ) {
    if( pseudocount >= 2 ) {
      if( "]" >< rrayval ) {
        pseudocount--;
        tmpf = ereg_replace( pattern:"\[|\]", string:rrayval, replace:"" );
        data[pseudocount] = tmpf;
      } else {
        param[pseudocount] = rrayval;
      }
    } else {
      param[pseudocount] = rrayval;
    }
    pseudocount++;
  }

  for( z = 2; z < max_index( param ); z++ ) {
    url = string( param[0], "?" );
    for( i = 2; i < max_index( param ); i++ ) {
      if( z == i ) {
        url += param[i] + "=" + ex;
      } else {
        if( data[i] ) {
          url += param[i] + "=" + data[i];
        } else {
          url += param[i] + "=";
        }
      }
      if( param[i + 1] ) {
        url += "&";
      }
    }
    urls = make_list( urls, url + "&" );
  }
  return urls;
}

# Returns an array containing the following index:
# basic_auth = TRUE/FALSE if Basic Auth is available/found
# realm      = A string containing the Basic Auth realm or "Undefined/Unknown" if none found
function extract_basic_auth( data ) {

  local_var data, header, infos, realm;

  infos = make_array( "basic_auth", FALSE,
                      "realm", "Undefined/Unknown" );

  if( ! data ) {
    set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#data#-#extract_basic_auth" );
    return infos;
  }

  if( ! header = egrep( pattern:"^WWW-Authenticate: Basic", string:data, icase:TRUE ) )
    return infos;

  infos["basic_auth"] = TRUE;

  realm = eregmatch( pattern:"realm=(.*)", string:header, icase:TRUE );
  if( realm[1] ) infos["realm"] = chomp( realm[1] );

  return infos;
}

# @brief This function returns the info if a remote web server was internally
#        (in the KB) marked as "broken". It will also save the information in
#        an internal array to avoid that redis is queried.
#
# @param port        the port of the remote server
#
# @return TRUE if the remote web server was marked as broken, FALSE otherwise and
#              NULL in the case where the port parameter wasn't passed.
#
function http_is_marked_broken( port ) {

  local_var port, marked_broken;
  # nb: _http_is_broken_array is a global_var (see on top)

  if( ! port ) {
    set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#extract_location_from_redirect" );
    return NULL;
  }

  # Used to not query redis with the get_kb_item below
  # to save some requests.
  if( ! isnull( _http_is_broken_array[port] ) ) {
    if( _http_is_broken_array[port] )
      return TRUE;
    else
      return FALSE;
  }

  marked_broken = get_kb_item( "Services/www/" + port + "/broken" );
  if( marked_broken )
    _http_is_broken_array[port] = TRUE;
  else
    _http_is_broken_array[port] = FALSE;

  return marked_broken;
}