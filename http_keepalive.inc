###############################################################################
# OpenVAS Vulnerability Test
# $Id: http_keepalive.inc 7577 2017-10-26 10:41:56Z cfischer $
#
# Methods to support http keep alive handling
#
# Authors:
# Renaud Deraison
#
# Copyright:
# Copyright (C) 2005 Renaud Deraison
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#
# $Revision: 7577 $
#
###############################################################################

# Note that the file "http_func.inc" must also be included when
# using this file.

global_var __ka_socket, __ka_port, __ka_enabled, __ka_last_request;

__ka_socket = 0;
__ka_port   = 0;
__ka_enabled = -1;
__ka_last_request = "";

# Enables debugging output for a few functions below
global_var _http_ka_debug;
_http_ka_debug = 0;

# Based on the last headers we received, we determine if we need
# to close our socket and re-open it or not
function http_keepalive_check_connection( headers ) {

  local_var tmp;

  if( ! headers ) set_kb_item( name: "nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#headers#-#http_keepalive_check_connection" );

  tmp = egrep( pattern:"^Connection: Close", string:headers, icase:TRUE );
  if( tmp ) {
    if( __ka_socket ) {
      http_close_socket( __ka_socket );
    }
    __ka_socket = http_open_socket( __ka_port );
  }
}

function enable_keepalive( port ) {

  if( ! port ) set_kb_item( name: "nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#enable_keepalive" );

  __ka_enabled = 1;
  __ka_port    = port;
  __ka_socket  = http_open_socket( port );
}

#
# This function determines if the remote web server is
# keep-alive-enabled or not.
#
function http_keepalive_enabled( port ) {

  local_var req, soc, r, kb;

  if( ! port ) set_kb_item( name: "nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#http_keepalive_enabled" );

  kb = get_kb_item( strcat( "www/", port, "/keepalive" ) );

  if( kb == "yes" ) {
    enable_keepalive( port:port );
    return( 1 );
  } else if( kb == "no" ) {
    return( 0 );
  }

  host = http_host_name( port:port );

  req = strcat( 'GET / HTTP/1.1\r\n',
                'Connection: Keep-Alive\r\n',
                'Host: ', host, '\r\n',
                'Pragma: no-cache\r\n',
                'User-Agent: ' + OPENVAS_HTTP_USER_AGENT + '\r\n\r\n' );

  soc = http_open_socket( port );
  if( ! soc ) return -2;
  send( socket:soc, data:req );
  r = http_recv( socket:soc );

  # Apache
  if( egrep( pattern:"^Keep-Alive:.*", string:r, icase:TRUE ) ) {
    http_close_socket( soc );
    set_kb_item( name:strcat( 'www/', port, '/keepalive' ), value:"yes" );
    enable_keepalive( port:port );
    return( 1 );
  } else {
    # IIS
    send( socket:soc, data:req );
    r = http_recv( socket:soc );
    http_close_socket( soc );
    if( strlen( r ) ) {
      set_kb_item( name:strcat( "www/", port, "/keepalive" ), value:"yes" );
      enable_keepalive( port:port );
      return( 1 );
    }
  }

  set_kb_item( name:strcat( "www/", port, "/keepalive" ), value:"no" );
  return( 0 );
}

#
# This function is akin to http_recv_body() except that if the last request
# was a HEAD, we bail out (whereas http_recv() will timeout).
#
function http_keepalive_recv_body( headers, bodyonly ) {

  local_var body, length, tmp, chunked, killme, gzip;

  if( ! headers ) set_kb_item( name: "nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#headers#-#http_keepalive_recv_body" );

  killme = 0;
  length = -1;

  if( ereg( pattern:"^HEAD.*HTTP/.*", string:__ka_last_request ) ) {
    # HEAD does not return a body
    http_keepalive_check_connection( headers:headers );
    if( bodyonly ) {
      return( "" );
    } else {
      return( headers );
    }
  }

  if( "content-length: " >< tolower( headers ) ) {
    tmp = egrep( string:headers, pattern:"^Content-Length: *[0-9]+", icase:TRUE );
    if( tmp ) length = int( ereg_replace( string:tmp, pattern:"^Content-Length: *([0-9]*) *", replace:"\1", icase:TRUE ) );
  }

  if( "content-encoding: gzip" >< tolower( headers ) ) gzip = TRUE;

  if( ( length < 0 ) && ( egrep( pattern:"transfer-encoding: chunked", string:headers, icase:TRUE ) ) ) {
    while( 1 ) {
      tmp = recv_line( socket:__ka_socket, length:4096 );
      length = hex2dec( xvalue:tmp );
      if( length > 1048576 ) {
        length = 1048576;
        killme = 1;
      }
      body  = strcat( body, recv( socket:__ka_socket, length:length, min:length ) );
      # "\r\n"
      recv( socket:__ka_socket, length:2, min:2 );
      if( strlen( body ) > 1048576 ) killme = 1;

      if( length == 0 || killme ) {
        http_keepalive_check_connection( headers:headers );
        # This is expected - don't put this line before the previous
        if( gzip )
          body = http_gunzip( buf:body, onlybody:TRUE );

        if( bodyonly ) {
          return( body );
        } else {
          return( strcat( headers, '\r\n', body ) );
        }
      }
    }
  }

  if( length >= 0 ) {
    # Don't receive more than 1 MB
    if( length > 1048576 ) length = 1048576;

    body = recv( socket:__ka_socket, length:length, min:length );
  } else {
    # If we don't have the length, we close the connection to make sure
    # the next request won't mix up the replies.

    if( _http_ka_debug ) display("ERROR - Keep Alive, but no length!!!\n", __ka_last_request);
    body = recv( socket:__ka_socket, length:16384, min:0 );
    if( body =~ '<html[^>]*>' && body !~ '</html>' ) { # case insensitive
      repeat {
        tmp = recv( socket:__ka_socket, length:16384 );
        body += tmp;
      }
      until( ! tmp || body =~ "</html>" );
      if( _http_ka_debug && body !~ "</html>" ) display( "http_keepalive_recv_body: incomplete body?\n------------\n", body, "\n------------\n" );
    }
    http_close_socket( __ka_socket );
    __ka_socket = http_open_socket( __ka_port );
  }

  http_keepalive_check_connection( headers:headers );

  if( gzip )
    body = http_gunzip( buf:body, onlybody:TRUE );

  if( bodyonly ) {
    return( body );
  } else {
    return( strcat( headers, '\r\n', body ) );
  }
}

# We close our socket on exit.
function on_exit() {
  if( __ka_socket ) {
    http_close_socket( __ka_socket );
    __ka_socket = 0;
  }
}

if( 0 ) on_exit(); #TBD: Whats the purpose of this?

#
# This is our "public" Keep-Alive function. It sends <data> to the remote
# host on port <port>, and returns the result, or NULL if no connection
# could be established.
#
function http_keepalive_send_recv( port, data, bodyonly, fetch404, content_type_body_only, headersonly ) {

  local_var headersonly;
  local_var id, n, ret, headers;
  local_var soc, r, body, lendata;

  if( ! port ) {
    set_kb_item( name: "nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#http_keepalive_send_recv" );
    return NULL;
  }

  if( ! data ) {
    set_kb_item( name: "nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#data#-#http_keepalive_send_recv" );
    return NULL;
  }

  # http_get() won't add a Host: header if only HTTP/1.0 support was detected
  if( "Host:" >!< data && "HTTP/1.0" >!< data ) {
    set_kb_item( name:"nvt_debug_misc/" + get_script_oid(), value:get_script_oid() + "#-#No 'Host:' header passed in data variable of http_keepalive_send_recv(). This might lead to issues if SNI is enabled on the remote host." );
  }

  if( _http_ka_debug ) display( "http_keepalive_send_recv( port: ", port, ", data: ", data, ", bodyonly: ", bodyonly, " )\n" );

  if( __ka_enabled == -1 ) __ka_enabled = http_keepalive_enabled( port:port );
  if( __ka_enabled == -2 ) return NULL;

  if( __ka_enabled == 0 ) {
    soc = http_open_socket( port );
    if( ! soc ) return NULL;
    if( send( socket:soc, data:data ) <= 0 ) {
      http_close_socket( soc );
      return NULL;
    }
    headers = http_recv_headers2( socket:soc );
    # If the headers are not HTTP compliant, just return right away
    if( headers && ! ereg( pattern:"^HTTP/.* [0-9]+", string:headers ) ) {
      http_close_socket( soc );
      return headers;
    }

    # Allows to fetch pages with e.g. only Content-Type: text/html by passing
    # a regex like "^Content-Type: text/(xml|html)"
    if( content_type_body_only ) {
      if( "content-type: " >< tolower( headers ) ) {
        if( ! egrep( pattern:content_type_body_only, string:headers, icase:TRUE ) ) {
          http_close_socket( soc );
          return headers;
        }
      }
    }

    if( headers && ( ! ereg( pattern:"^HTTP/.* 404", string:headers ) || fetch404 == TRUE ) )
      body = http_recv_body( socket:soc, headers:headers, length:0 );

    http_close_socket( soc );

    if( "content-encoding: gzip" >< tolower( headers ) )
      body = http_gunzip( buf:body, onlybody:TRUE );

    if( headersonly ) {
      return( headers );
    }

    if( bodyonly ) {
      return( body );
    } else {
      return( strcat( headers, '\r\n', body ) );
    }
  }

  if( ( port != __ka_port ) || ( ! __ka_socket ) ) {
    if( __ka_socket ) http_close_socket( __ka_socket );
    __ka_port = port;
    __ka_socket = http_open_socket( port );
    if( ! __ka_socket ) return NULL;
  }

  id = stridx( data, '\r\n\r\n' );
  # Old behavior: data = str_replace( string:data, find:"Connection: Close", replace:"Connection: Keep-Alive", count:1 );
  # https://tools.ietf.org/html/rfc7230#section-6.1 -> Connection options are case-insensitive.
  # Some NVTs devs might add a "Connection: close" to the header data passed to this function so doing an ereg_replace instead
  # nb: Be aware that this ereg_replace is also replacing any occurance of "Connection: Close" somewhere in the body of the request data.
  data = ereg_replace( string:data, pattern:"Connection: Close", replace:"Connection: Keep-Alive", icase:TRUE );
  __ka_last_request = data;
  n = send( socket:__ka_socket, data:data );
  lendata = strlen( data );
  if( n >= lendata )
    headers = http_recv_headers2( socket:__ka_socket );
  if( ! headers ) {
    http_close_socket( __ka_socket );
    __ka_socket = http_open_socket( __ka_port );
    if( __ka_socket == 0 ) return NULL;
    if( send( socket:__ka_socket, data:data ) < lendata ) {
      http_close_socket( __ka_socket );
      __ka_socket = NULL;
      return NULL;
    }
    headers = http_recv_headers2( socket:__ka_socket );
  }

  if( headersonly ) {
    return( headers );
  }

  # Allows to fetch pages with e.g. only Content-Type: text/html by passing
  # a regex like "^Content-Type: text/(xml|html)"
  if( content_type_body_only ) {
    if( "content-type: " >< tolower( headers ) ) {
      if( ! egrep( pattern:content_type_body_only, string:headers, icase:TRUE ) ) return headers;
    }
  }
  return http_keepalive_recv_body( headers:headers, bodyonly:bodyonly );
}

#
# Same as check_win_dir_trav(), but with KA support
#
function check_win_dir_trav_ka( port, url ) {

  local_var soc, req, cod, buf;

  if( ! port ) set_kb_item( name: "nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#check_win_dir_trav_ka" );
  if( ! url ) set_kb_item( name: "nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#url#-#check_win_dir_trav_ka" );

  req = http_get( item:url, port:port );
  buf = http_keepalive_send_recv( port:port, data:req );

  if( "; for 16-bit app support" >< buf || "[boot loader]" >< buf ) {
    return( 1 );
  }
  return( 0 );
}

function is_cgi_installed_ka( item, port ) {

  local_var r, no404, dir, slash, dirs, banner;

  if( ! port ) set_kb_item( name: "nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#is_cgi_installed_ka" );

  if( get_kb_item( "Settings/disable_cgi_scanning" ) ) return 0;

  banner = get_http_banner( port:port );
  if( item[0] != "/" ) {
    dirs = cgi_dirs( port:port );
    slash = "/";
  } else {
    dirs = make_list( "" );
    slash = "";
  }

  no404 = get_kb_item( strcat( "www/no404/", port ) );
  if( strlen( no404 ) >= 1 ) return NULL;

  foreach dir( dirs ) {

    if( dir == "/" ) dir = "";

    # some server return a 404 for / but sometimes not for all subdirs. so check again...
    t =  http_keepalive_send_recv( port:port, data:http_get( item:dir + slash + item + '_' + rand(), port:port ) );

    if( t !~ "HTTP/1\.. 404" ) continue;

    r = http_keepalive_send_recv( port:port, data:http_get( item:dir + slash + item, port:port ) );
    if( r == NULL ) continue;

    if( r =~ "^HTTP/1\.[0-9.] +200 +" && "Proxy-Agent: IWSS" >!< r ) {
      if( no404 && tolower( no404 ) >< tolower( r ) ) {
        continue;
      } else {
        return( 1 );
      }
    }
  }
  return( 0 );
}

function get_http_page( port, url, redirect ) {

  local_var r, u, v, i, l, seen_loc, n;

  if( ! port ) set_kb_item( name: "nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#get_http_page" );
  if( ! port ) set_kb_item( name: "nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#url#-#get_http_page" );

  if( isnull( redirect ) ) {
    n = 32;
  } else if( redirect <= 0 ) {
    n = 1;
  } else {
    n = redirect + 1;
  }

  seen_loc = make_list();
  u = url;
  for( i = 0; i < n; i ++ ) { # Limited iterations to avoid traps
    seen_loc[u] = 1;
    r = http_keepalive_send_recv( port:port, data:http_get( port:port, item:u ) );
    if( isnull( r ) ) return NULL;

    if( r =~ "^HTTP/1\.[01] +30[0-9] .*" ) {
      v = eregmatch( pattern:'\r\nLocation: *([^ \t\r\n]+)[ \t]*[\r\n]+', string:r, icase:TRUE );
      if( isnull( v ) ) return NULL; # Big problem
      l = v[1];
      if( seen_loc[l] ) return NULL;
      seen_loc[l] = 1;
    } else if( r =~ "^HTTP/1\.[01] +200 " ) {
      r = strstr( r, '\r\n\r\n' );
      r = substr( r, 4 );
      return r;
    } else { # Code 4xx or 5xx
      return NULL;
    }
  }
  # Loop?
  return NULL;
}

function http_get_cache( port, item ) {

  local_var port, item, req, res;

  if( ! port ) set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#http_get_cache" );
  if( ! item ) set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#item#-#http_get_cache" );

  res = get_kb_item( "Cache/" + port + "/URL_" + item );
  if( res ) return res;

  req = http_get( port:port, item:item );
  res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );
  if( ! res ) return NULL;

  # Only save a valid HTTP response into the KB. We also
  # don't want so save the following HTTP status codes
  # into our cache which might be just temporary:
  # Internal Server Errors (5xx)
  # Too Many Requests (429)
  # Request Timeout (408)
  if( res !~ "^HTTP/1\.[01] 50[0-9]" &&
      res !~ "^HTTP/1\.[01] 51[01]" &&
      res !~ "^HTTP/1\.[01] 408" &&
      res !~ "^HTTP/1\.[01] 429" &&
      res =~ "^HTTP/1\.[01]" ) {
    replace_kb_item( name:"Cache/" + port + "/URL_" + item, value:res );
  }

  return res;
}

function http_check_remote_code( default_port, extra_dirs, unique_dir, check_request, extra_check, check_result, command, port ) {

  local_var list, req, txt_result, txt_desc, extra, dir, buf;

  if( get_kb_item( "Settings/disable_cgi_scanning" ) ) exit( 0 );

  if( ! check_request ) set_kb_item( name: "nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#check_request#-#http_check_remote_code" );
  if( ! check_result ) set_kb_item( name: "nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#check_result#-#http_check_remote_code" );
  if( ! command ) set_kb_item( name: "nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#command#-#http_check_remote_code" );

  if( ! port ) {
    if( default_port ) {
      port = get_http_port( default:default_port );
    } else {
      port = get_http_port( default:80 );
   }
  }

  if( ! get_port_state( port ) ) exit( 0 );

  if( unique_dir ) {
    list = make_list( unique_dir );
  } else {
    if( ! isnull( extra_dirs ) ) {
      list = make_list( cgi_dirs( port:port ), extra_dirs );
    } else {
      list = make_list( cgi_dirs( port:port ) );
    }
  }

  foreach dir( list ) {

    req = string( dir, check_request );
    req = http_get( item:req, port:port );
    buf = http_keepalive_send_recv( port:port, data:req );
    if( buf == NULL ) exit( 0 ); #TBD: Really exit?

    txt_result = egrep( pattern:check_result, string:buf );
    if( extra_check ) {
      extra = 0;
      if( egrep( pattern:extra_check, string:buf ) ) {
        extra = 1;
      }
    } else {
      extra = 1;
    }

    if( txt_result && extra ) {
      txt_desc = 'It was possible to execute the command "' + command + '" on the remote host, which produces the following output:\n\n' + txt_result;
      security_message( port:port, data:txt_desc );
      exit( 0 );
    }
  }
}

function http_vuln_check( port, url, pattern, check_header, debug, extra_check, hostname, cookie, check_nomatch, icase ) {

  local_var port, url, pattern, check_header, debug, extra_check, hostname, cookie, check_nomatch;
  local_var req, buf, ec, nm, icase;

  if( ! url ) {
    set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#url#-#http_vuln_check" );
    return FALSE;
  }

  if( ! port ) {
    set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#http_vuln_check" );
    return FALSE;
  }

  if( isnull( pattern ) || pattern == "" ) {
    set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#pattern#-#http_vuln_check" );
    return FALSE;
  }

  if( isnull( icase ) ) icase = TRUE;

  req = http_get( item:url, port:port );

  if( COMMAND_LINE ) { # set hostname for vhosts on command line if hostname parameter was given.
    if( hostname ) {
      req = ereg_replace( string:req, pattern:"Host:.*" + get_host_ip(), replace: "Host: " + hostname );
    }
  }

  if( cookie && ! isnull( cookie ) )
    req = ereg_replace( string:req, pattern:'\r\n\r\n', replace: '\r\nCookie: ' + cookie + '\r\n\r\n' );

  buf = http_keepalive_send_recv( port:port, data:req );
  if( buf == NULL ) return FALSE;

  __ka_last_request = req;

  if( debug ) {
    display( "\nContent:\n", buf, "\n" );
  }

  if( check_header == TRUE ) {
    if( ! ereg( pattern:"^HTTP/[0-9]\.[0-9] 200.*", string:buf ) ) {
      return FALSE;
    }
  }

  ## Extra check for Strings to match in the buf
  if( extra_check ) {
    if( typeof( extra_check ) != "array" ) {
      extra_check = make_list( extra_check );
    }

    foreach ec( extra_check ) {
      if( ! egrep( pattern:ec, string:buf, icase:icase ) ) {
        return FALSE;
      }
    }
  }

  ## Check for Strings that should not match in buf
  if( check_nomatch ) {
    if( typeof( check_nomatch ) != "array" ) {
      check_nomatch = make_list( check_nomatch );
    }

    foreach nm( check_nomatch ) {
      if( egrep( pattern:nm, string:buf, icase:icase ) ) {
        return FALSE;
      }
    }
  }

  if( egrep( pattern:pattern, string:buf, icase:icase ) ) {
    return buf;
  }
  return FALSE;
}

function report_vuln_url( port, url, url_only ) {

  local_var proto, host, report, port, url, url_only;

  if( ! port ) set_kb_item( name: "nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#report_vuln_url" );
  if( ! url ) set_kb_item( name: "nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#url#-#report_vuln_url" );

  proto = 'http';
  if( get_port_transport( port ) > ENCAPS_IP ) proto = 'https';

  host = http_host_name( port:port );

  if( url_only ) {
    report = proto + '://' + host + url;
  } else {
    report = 'Vulnerable url: ' + proto + '://' + host + url;
  }

  return report;
}

# req = http_post_req( port:port, url:"/", data:data, accept_header:"application/json", add_headers: make_array( "Content-Type", "application/x-www-form-urlencoded" ) );
function http_post_req( port, url, data, add_headers, accept_header ) {

  local_var req, port, data, add_headers, header, accept_header, url, len, host;

  if( ! isnull( add_headers ) ) {
    if( typeof( add_headers ) != "array" ) {
      set_kb_item( name: "nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#add_headers_no-array#-#http_post_req" );
      return;
    }
  }

  if( ! port ) {
    set_kb_item( name: "nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#http_post_req" );
    return;
  }

  if( ! url ) url = "/";

  if( data ) len = strlen( data );

  host = http_host_name( port:port );
  if( ! accept_header ) accept_header = '*/*';

  req = 'POST ' + url + ' HTTP/1.1\r\n' +
        'Host: ' + host + '\r\n' +
        'Pragma: no-cache\r\n' +
        'User-Agent: ' + OPENVAS_HTTP_USER_AGENT + '\r\n' +
        'Accept-Language: en\r\n' +
        'Accept-Charset: iso-8859-1,utf-8;q=0.9,*;q=0.1\r\n' +
        'Accept: ' + accept_header + '\r\n' +
        'Accept-Encoding: identity\r\n';

  if( data ) req += 'Content-Length: ' + len + '\r\n';

  if( ! isnull( add_headers ) ) {
    foreach header( keys( add_headers ) )
      req += header +': ' + add_headers[header] + '\r\n';
  }

  req += '\r\n';

  if( data ) req += data;

  return req;
}

function http_get_req( port, url, add_headers, accept_header, user_agent ) {

  local_var req, port, add_headers, header, url, accept_header, host, x_header;

  if( ! isnull( add_headers ) ) {
    if( typeof( add_headers ) != "array" ) {
      set_kb_item( name: "nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#add_headers_no-array#-#http_get_req" );
      return;
    }
  }

  if( ! port ) {
    set_kb_item( name: "nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#http_get_req" );
    return;
  }

  if( ! url ) url = "/";
  x_header = FALSE;

  host = http_host_name( port:port );
  if( ! accept_header ) accept_header = 'image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, image/png, */*';

  if ( ! user_agent )
    user_agent = OPENVAS_HTTP_USER_AGENT;
  else
    x_header = TRUE;

  req = 'GET ' + url + ' HTTP/1.1\r\n' +
        'Connection: Close\r\n' +
        'Host: ' + host + '\r\n' +
        'Pragma: no-cache\r\n' +
        'Cache-Control: no-cache\r\n' +
        'User-Agent: ' + user_agent + '\r\n' +
        'Accept: ' + accept_header + '\r\n' +
        'Accept-Language: en\r\n' +
        'Accept-Charset: iso-8859-1,*,utf-8\r\n';

  if( x_header )
    req += 'X-Scanner: OpenVAS ' + OPENVAS_VERSION + '\r\n';

  if( ! isnull( add_headers ) ) {
    foreach header( keys( add_headers ) )
      req += header +': ' + add_headers[header] + '\r\n';
  }

  req += '\r\n';

  return req;
}

function recv_http_buf( port, url, bodyonly, nocache )
{
  local_var port, url, bodyonly, nocache, req;

  if( ! port ) {
    set_kb_item( name: "nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#recv_http_buf" );
    return;
  }

  if( ! url ) {
    set_kb_item( name: "nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#url#-#recv_http_buf" );
    return;
  }

  if( ! nocache )
  {
    if( ! egrep( pattern:"(\?|&|#|;|\[|\]|=)", string:url  ) )
      return http_get_cache( item:url,
                             port:port );

  }

  req = http_get( item:url, port:port );
  return http_keepalive_send_recv( port:port,
                                   data:http_get( item:url, port:port ),
                                   bodyonly:bodyonly );

  return;

}

