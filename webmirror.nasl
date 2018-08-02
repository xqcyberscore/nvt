###############################################################################
# OpenVAS Vulnerability Test
# $Id: webmirror.nasl 10713 2018-08-01 14:21:58Z cfischer $
#
# WEBMIRROR 2.0
#
# Saved from
# http://patch-tracker.debian.org/patch/misc/view/nessus-plugins/2.2.10-6/scripts/webmirror.nasl
# (nessus internal revision 1.86 released with 2.2.0 in November 2004 under GNU GPL terms)
#
# Authors:
# Renaud Deraison <deraison@nessus.org>.
#
# includes some code by H D Moore <hdmoore@digitaldefense.net>
#
# Modified by Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2001 - 2003 Renaud Deraison
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
  script_oid("1.3.6.1.4.1.25623.1.0.10662");
  script_version("$Revision: 10713 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-01 16:21:58 +0200 (Wed, 01 Aug 2018) $");
  script_tag(name:"creation_date", value:"2009-10-02 19:48:14 +0200 (Fri, 02 Oct 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Web mirroring");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2001 - 2003 Renaud Deraison");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "httpver.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  # Keep the settings of MAIN() in sync when changing the settings here
  script_add_preference(name:"Number of pages to mirror : ", type:"entry", value:"200");
  script_add_preference(name:"Start page : ", type:"entry", value:"/");
  script_add_preference(name:"Number of cgi directories to save into KB : ", type:"entry", value:"128");

  script_add_preference(name:"Regex pattern to exclude cgi scripts : ", type:"entry", value:"\.(js|css)$");
  script_add_preference(name:"Use regex pattern to exclude cgi scripts : ", type:"checkbox", value:"yes");

  script_tag(name:"summary", value:"This script makes a mirror of the remote web site
  and extracts the list of CGIs that are used by the remote host.

  It is suggested that you allow a long-enough timeout value for this test routine and also
  adjust the setting on the number of pages to mirror.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_timeout(900);

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

# Keep this in sync with the preferences in the description part
start_page = script_get_preference( "Start page : " );
if( isnull( start_page ) || start_page == "" ) start_page = "/";

max_pages = int( script_get_preference( "Number of pages to mirror : " ) );
if( max_pages <= 0 ) max_pages = 200;

max_cgi_dirs = int( script_get_preference( "Number of cgi directories to save into KB : " ) );
if( max_cgi_dirs <= 0 ) max_cgi_dirs = 128;

cgi_dirs_exclude_pattern = get_kb_item( "global_settings/cgi_dirs_exclude_pattern" );
use_cgi_dirs_exclude_pattern = get_kb_item( "global_settings/use_cgi_dirs_exclude_pattern" );
cgi_dirs_exclude_servermanual = get_kb_item( "global_settings/cgi_dirs_exclude_servermanual" );

# Skip .js and .css files by default as their parameters are just cache busters
cgi_scripts_exclude_pattern = script_get_preference( "Regex pattern to exclude cgi scripts : " );
if( ! cgi_scripts_exclude_pattern ) cgi_scripts_exclude_pattern = "\.(js|css)$";

use_cgi_scripts_exclude_pattern = script_get_preference( "Use regex pattern to exclude cgi scripts : " );

#counter for current failed requests
failedReqs = 0;
#counter for max failed requests
#The NVT will exit if this is reached
#TBD: Make this configurable?
maxFailedReqs = 3;

# Current number of evaluated cgi dirs
num_cgi_dirs = 0;

debug = 0;

URLs_hash        = make_list();
CGIs             = make_list();
Misc             = make_list();
Dirs             = make_list();
PW_inputs        = make_list();
URLs_30x_hash    = make_list();
URLs_auth_hash   = make_list();
Code404          = make_list();
URLs_discovered  = make_list();
Check401         = TRUE;
recur_candidates = make_array();

URLs_hash[start_page] = 0;
cnt = 0;

RootPasswordProtected = FALSE;
Apache  = FALSE;
iPlanet = FALSE;

function add_cgi_dir( dir, append_pattern, port, host ) {

  local_var dir, append_pattern, port, host, req, res;

  dir = dir( url:dir );

  if( dir && ! Dirs[dir] ) {

    if( num_cgi_dirs > max_cgi_dirs ) {
      set_kb_item( name:"www/" + port + "/content/skipped_directories", value:dir );
      set_kb_item( name:"www/" + host + "/" + port + "/content/skipped_directories", value:dir );
      return;
    }

    if( use_cgi_dirs_exclude_pattern ) {
      if( egrep( pattern:cgi_dirs_exclude_pattern, string:dir ) ) {
        set_kb_item( name:"www/" + port + "/content/excluded_directories", value:dir );
        set_kb_item( name:"www/" + host + "/" + port + "/content/excluded_directories", value:dir );
        return;
      }
    }

    req = http_get( item:dir + "/non-existent-" + rand(), port:port );
    res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

    # Only add as cgi dir if the directory is throwing a 404 on non-existent files
    if( res =~ "^HTTP/1\.[01] 404" ) {

      Dirs[dir] = 1;
      set_kb_item( name:"www/" + port + "/content/directories", value:dir );
      set_kb_item( name:"www/" + host + "/" + port + "/content/directories", value:dir );
      num_cgi_dirs++;

      if( isnull( URLs_hash[dir] ) ) {
        URLs_discovered = make_list( URLs_discovered, dir );
        # Appending this pattern everywhere seems to cause undetected directory indexes
        if( append_pattern ) {
          if( Apache ) {
            URLs_discovered = make_list( URLs_discovered, dir + "/?D=A" );
          } else if( iPlanet ) {
            URLs_discovered = make_list( URLs_discovered, dir + "/?PageServices" );
          }
        }
        URLs_hash[dir] = 0;
      }
    }
  }
}

function add_30x( url, port, host ) {

  local_var url, port, host;

  if( isnull( URLs_30x_hash[url] ) ) {
    set_kb_item( name:"www/" + port + "/content/30x", value:url );
    set_kb_item( name:"www/" + host + "/" + port + "/content/30x", value:url );
    URLs_30x_hash[url] = 1;
  }
}

function add_auth( url, basic, realm, port, host ) {

  local_var url, basic, realm, port, host;

  if( isnull( URLs_auth_hash[url] ) ) {

    # Skipping if the "Test for servers which return 401 for everything" was successful.
    # But at least add the "/" root folder to it.
    if( ! Check401 && url != "/" ) return;

    set_kb_item( name:"www/content/auth_required", value:TRUE );
    set_kb_item( name:"www/" + host + "/" + port + "/content/auth_required", value:url );

    URLs_auth_hash[url] = 1;
    if( url == "/" ) RootPasswordProtected = TRUE;

    # Used in 2018/gb_http_cleartext_creds_submit.nasl
    if( basic ) {
      set_kb_item( name:"www/basic_auth/detected", value:TRUE );
      set_kb_item( name:"www/pw_input_field_or_basic_auth/detected", value:TRUE );

      # Used in 2018/gb_http_cleartext_creds_submit.nasl
      set_kb_item( name:"www/" + port + "/content/basic_auth/" + url, value:report_vuln_url( port:port, url:url, url_only:TRUE ) + ":" + realm );
      set_kb_item( name:"www/" + host + "/" + port + "/content/basic_auth/" + url, value:report_vuln_url( port:port, url:url, url_only:TRUE ) + ":" + realm );
    }
  }
}

function add_url( url, port, host ) {

  local_var url, port, host, ext, dir;

  if( url == "." ) url = "/";

  if( debug > 5 ) display( "**** ADD URL ", url, "\n" );

  #TBD: Check URL before adding it?
  #Tests shown a difference between 4min without vs. 10min with

  if( isnull( URLs_hash[url] ) ) {

    URLs_discovered = make_list( URLs_discovered, url );
    URLs_hash[url]  = 0;

    url = ereg_replace( string:url, pattern:"(.*)[;?].*", replace:"\1" );
    ext = ereg_replace( pattern:".*\.([^\.]*)$", string:url, replace:"\1" );

    if( strlen( ext ) && ext[0] != "/" ) {
      set_kb_item( name:"www/" + port + "/content/extensions/" + ext, value:url );
      set_kb_item( name:"www/" + host + "/" + port + "/content/extensions/" + ext, value:url );
      if( ext == "action" || ext == "jsp" || ext == "do" )
        set_kb_item( name:"www/action_jsp_do", value:TRUE );
    }
    add_cgi_dir( dir:url, append_pattern:TRUE, port:port, host:host ); # Append the "/?PageServices and" "/?D=A"
  }
}

function cgi2hash( cgi ) {

  local_var cgi, cur_cgi, cur_arg, i, ret, len;

  ret = make_list();
  len = strlen( cgi );

  for( i = 0; i < len; i++ ) {
    if( cgi[i] == " " && i + 1 < len && cgi[i+1] == "[" ) {
    cur_arg = "";
    for( i = i + 2; i < len; i++ ) {
      if( cgi[i] == "]" ) {
        ret[cur_cgi] = cur_arg;
        cur_cgi = "";
        cur_arg = "";
        if( i + 2 >= len ) return ret;
        i += 2;
        break;
      } else {
        cur_arg += cgi[i];
      }
    }
  }
  cur_cgi += cgi[i];
  }
  return ret;
}

function hash2cgi( hash ) {

  local_var hash, ret, h;

  ret = "";
  foreach h( keys( hash ) ) {
    ret += string( h, " [", hash[h], "] " );
  }
  return ret;
}

function add_cgi( cgi, args, port, host ) {

  local_var cgi, args, port, host;
  local_var tmp, new_args, common, c;

  # Don't add cgis for pattern we have added ourselves
  if( "/?D=A" >< cgi || "/?PageServices" >< cgi ) return;

  if( cgi == "." ) cgi = "/";

  args = string( args );

  if( isnull( CGIs[cgi] ) ) {

    CGIs[cgi] = args;
    add_cgi_dir( dir:cgi, port:port, host:host );
    args = CGIs[cgi];
    if( ! args ) args = "";

    if( use_cgi_scripts_exclude_pattern != "no" ) {
      if( egrep( pattern:cgi_scripts_exclude_pattern, string:cgi ) ) {
        replace_kb_item( name:"www/" + port + "/content/excluded_cgis/" + cgi, value:report_vuln_url( port:port, url:cgi, url_only:TRUE ) + " (" + args + ")" );
        replace_kb_item( name:"www/" + host + "/" + port + "/content/excluded_cgis/" + cgi, value:report_vuln_url( port:port, url:cgi, url_only:TRUE ) + " (" + args + ")" );
        return;
      }
    }

    set_kb_item( name:"www/" + port + "/cgis", value:cgi + " - " + args );
    set_kb_item( name:"www/" + host + "/" + port + "/cgis", value:cgi + " - " + args );
    replace_kb_item( name:"www/" + port + "/content/cgis/" + cgi, value:report_vuln_url( port:port, url:cgi, url_only:TRUE ) + " (" + args + ")" );
    replace_kb_item( name:"www/" + host + "/" + port + "/content/cgis/" + cgi, value:report_vuln_url( port:port, url:cgi, url_only:TRUE ) + " (" + args + ")" );

  } else {

    tmp = cgi2hash( cgi:CGIs[cgi] );
    new_args = cgi2hash( cgi:args );
    common = make_list();

    foreach c( keys( tmp ) ) {
      common[c] = tmp[c];
    }

    foreach c( keys( new_args ) ) {
      if( isnull( common[c] ) ) {
        common[c] = new_args[c];
      }
    }
    CGIs[cgi] = hash2cgi( hash:common );
    args = CGIs[cgi];
    if( ! args ) args = "";

    if( use_cgi_scripts_exclude_pattern != "no" ) {
      if( egrep( pattern:cgi_scripts_exclude_pattern, string:cgi ) ) {
        replace_kb_item( name:"www/" + port + "/content/excluded_cgis/" + cgi, value:report_vuln_url( port:port, url:cgi, url_only:TRUE ) + " (" + args + ")" );
        replace_kb_item( name:"www/" + host + "/" + port + "/content/excluded_cgis/" + cgi, value:report_vuln_url( port:port, url:cgi, url_only:TRUE ) + " (" + args + ")" );
        return;
      }
    }

    set_kb_item( name:"www/" + port + "/cgis", value:cgi + " - " + args );
    set_kb_item( name:"www/" + host + "/" + port + "/cgis", value:cgi + " - " + args );
    replace_kb_item( name:"www/" + port + "/content/cgis/" + cgi, value:report_vuln_url( port:port, url:cgi, url_only:TRUE ) + " (" + args + ")" );
    replace_kb_item( name:"www/" + host + "/" + port + "/content/cgis/" + cgi, value:report_vuln_url( port:port, url:cgi, url_only:TRUE ) + " (" + args + ")" );
  }
}

function dir( url ) {
  local_var url;
  return ereg_replace( pattern:"(.*)/[^/]*", string:url, replace:"\1" );
}

function remove_cgi_arguments( url, port, host ) {

  local_var url, port, host;
  local_var len, idx, cgi, cgi_args, arg, args, a, b;

  # Remove the trailing blanks
  while( url[ strlen( url ) - 1] == " " ) {
    url = substr( url, 0, strlen( url ) - 2);
  }

  # New length after removing the trailing blanks
  len = strlen( url );

  idx = stridx( url, "?" );
  if( idx < 0 ) {
    return url;
  } else if( idx >= len - 1 ) {
    cgi = substr( url, 0, len - 2 );
    add_cgi( cgi:cgi, args:"", port:port, host:host );
    return cgi;
  } else {
    if( idx > 1 ) {
      cgi = substr( url, 0, idx - 1 );
    } else {
      cgi = ".";
    }

    cgi_args = split( substr( url, idx + 1, len - 1 ), sep:"&" );

    foreach arg( make_list( cgi_args ) ) {

      arg = arg - "&";
      arg = arg - "amp;";
      a = ereg_replace( string:arg, pattern:"(.*)=.*", replace:"\1" );
      b = ereg_replace( string:arg, pattern:".*=(.*)", replace:"\1" );

      if( a != b ) {
        args = string( args, a, " [", b, "] " );
      } else {
        args = string( args, arg, " [] " );
      }
    }
    add_cgi( cgi:cgi, args:args, port:port, host:host );
    return cgi;
  }
}

function basename( name, level ) {

  local_var name, level, len, i;

  len = strlen( name );

  if( len == 0 ) return NULL;

  for( i = len - 1; i >= 0; i-- ) {
    if( name[i] == "/" ) {
      level--;
      if( level < 0 ) {
        return( substr( name, 0, i ) );
      }
    }
  }

  # Level is too high, we return /
  return "/";
}

function clean_url( url ) {

  local_var url, search, s;

  search = make_list( "'"," ",'"' );
  foreach s( search ) {
    if( ! isnull( url ) ) {
      url = str_replace( string:url, find:s, replace:"", keep:FALSE );
    }
  }
  return url;
}

# This function checks if the passed URL is a recursion candidate
# and returns TRUE if the same URL was previously collected two times
# and FALSE otherwise.
function check_recursion_candidates( url, current, port, host ) {

  local_var url, current, port, host, num;

  if( ! url ) return FALSE;

  # A few of those are already checked in canonical_url
  # but just checking again to be sure...
  # Examples without recursions:
  # <a href="#">example1</a>
  # <a href="./example2">example2</a>
  # <a href="/example3">example3</a>
  # <a href="../example4">example4</a>
  # <a href="./../example5">example5</a>
  # <a href="https://example6">example6</a>
  # <a href="//example7">example7</a>
  if( url =~ "^(https?|\.|/|#)" ) {
    if( debug > 3 ) display( "***** Not a recursion candidate: '", url, "'\n" );
    return FALSE;
  }

  # Recursion candidates are only links to subdirs
  if( "/" >!< url ) return FALSE;

  # e.g. if a 404 page contains a link like:
  # <link rel="icon" href="assets/img/favicon.ico" type="image/x-icon">
  # which would be a relative URL to a subfolder of the current path
  # throwing the same 404 page causing a recursion later...
  num = recur_candidates[url];
  if( num ) {
    num++;
    if( debug > 3 ) display( "***** Adding possible recursion candidate: '", url, "' (Count: ", num, ")\n" );
    recur_candidates[url] = num;
    if( num > 2 ) {
      if( debug > 3 ) display( "***** Max count ", num, " of recursion for: '", url, "' reached, skipping this URL.\n" );
      set_kb_item( name:"www/" + port + "/content/recursion_urls", value:current + " (" + url + ")" );
      set_kb_item( name:"www/" + host + "/" + port + "/content/recursion_urls", value:current + " (" + url + ")" );
      return TRUE;
    }
  } else {
    if( debug > 3 ) display( "***** Adding possible recursion candidate: '", url, "' (Count: 1)\n" );
    recur_candidates[url] = 1;
  }
  return FALSE;
}

function canonical_url( url, current, port, host ) {

  local_var url, current, port, host;
  local_var location, num_dots, i;

  url = clean_url( url:url );

  if( debug > 1 ) display( "***** canonical '", url, "' (current:", current, ")\n" );

  if( strlen( url ) == 0 ) return NULL;
  if( url[0] == "#" ) return NULL;

  if( url == "./" || url == "." || url =~ "^\./\?" ) return current;

  # We need to check for a possible recursion, see the function for some background notes.
  if( check_recursion_candidates( url:url, current:current, port:port, host:host ) ) return NULL;

  if( debug > 2 ) display( "**** canonical(again) ", url, "\n" );

  if( ereg( pattern:"[a-z]*:", string:url, icase:TRUE ) ) {
    if( ereg( pattern:"^http://", string:url, icase:TRUE ) ) {
      location = ereg_replace( string:url, pattern:"http://([^/]*)/.*", replace:"\1", icase:TRUE );
      if( location != url ) {
        # TBD: location could also contain the port, e.g. Location: http://example.com:1234/url
        if( location != get_host_name() ) {
          return NULL;
        } else {
          return remove_cgi_arguments( url:ereg_replace( string:url, pattern:"http://[^/]*/([^?]*)", replace:"/\1", icase:TRUE ), port:port, host:host );
        }
      }
    } else if( ereg( pattern:"^https://", string:url, icase:TRUE ) ) {
      location = ereg_replace( string:url, pattern:"https://([^/]*)/.*", replace:"\1", icase:TRUE );
      if( location != url ) {
        # TBD: location could also contain the port, e.g. Location: https://example.com:1234/url
        if( location != get_host_name() ) {
          return NULL;
        } else {
          return remove_cgi_arguments( url:ereg_replace( string:url, pattern:"https://[^/]*/([^?]*)", replace:"/\1", icase:TRUE ), port:port, host:host );
        }
      }
    }
  } else {
    if( url == "//" ) return "/";

    if( ereg( pattern:"^//.*", string:url, icase:TRUE ) ) {
      location = ereg_replace( string:url, pattern:"//([^/]*)/.*", replace:"\1", icase:TRUE );
      if( location != url ) {
        # TBD: location could also contain the port, e.g. Location: //example.com:1234/url
        if( location == get_host_name() ) {
          return remove_cgi_arguments( url:ereg_replace( string:url, pattern:"//[^/]*/([^?]*)", replace:"/\1", icase:TRUE ), port:port, host:host );
        }
     }
     return NULL;
    }

    if( url[0] == "/" ) {
      return remove_cgi_arguments( url:url, port:port, host:host );
    } else {
      i = 0;
      num_dots = 0;

      while( i < strlen( url ) - 2 && url[i] == "." && url[i+1] == "." && url[i+2] == "/" ) {
        num_dots++;
        url = url - "../";
        if( strlen( url ) == 0 ) break;
      }

      while( i < strlen( url ) && url[i] == "." && url[i+1] == "/" ) {
        url = url - "./";
        if( strlen( url ) == 0 ) break;
      }

      # Repeat again as some websites are doing stuff like <a href="./../foo"></a>
      while( i < strlen( url ) - 2 && url[i] == "." && url[i+1] == "." && url[i+2] == "/" ) {
        num_dots++;
        url = url - "../";
        if( strlen( url ) == 0 ) break;
      }

      url = string( basename( name:current, level:num_dots ), url );
    }

    i = stridx( url, "#" );
    if( i >= 0 ) url = substr( url, 0, i - 1 );

    if( url[0] != "/" ) {
      return remove_cgi_arguments( url:string("/", url ), port:port, host:host );
    } else {
      return remove_cgi_arguments( url:url, port:port, host:host );
    }
  }
  return NULL;
}

function extract_location( data, port, host ) {

  local_var data, port, host;
  local_var loc, url;

  loc = egrep( string:data, pattern:"^Location: " );
  if( ! loc ) return NULL;

  loc = loc - string( "\r\n" );
  loc = ereg_replace( string:loc, pattern:"Location: (.*)$", replace:"\1" );

  url = canonical_url( url:loc, current:"/", port:port, host:host );
  if( url ) {
    add_url( url:url, port:port, host:host );
    return url;
  }
  return NULL;
}

function retr( port, page, host ) {

  local_var port, page, host;
  local_var req, res, basic_auth, q;

  if( debug ) display( "*** RETR ", page, "\n" );

  # Send accept header and only get body of the page with a specific content-type
  req = http_get_req( url:page, port:port, accept_header:"text/html, text/xml" );
  res = http_keepalive_send_recv( port:port, data:req, fetch404:TRUE, content_type_body_only:"^Content-Type: text/(xml|html)", bodyonly:FALSE );

  if( res == NULL ) {
    failedReqs++;
    if( failedReqs >= maxFailedReqs ) {
      exit( 0 );
    }
    return NULL;
  }

  if( res !~ "^HTTP/1\.[01] 200" ) {
    if( res =~ "^HTTP/1\.[01] 40[13]" ) {
      if( egrep( pattern:"^WWW-Authenticate:", string:res, icase:TRUE ) ) {
        basic_auth = extract_basic_auth( data:res );
        add_auth( url:page, basic:basic_auth["basic_auth"], realm:basic_auth["realm"], port:port, host:host );
      }
      return NULL;
    }
    if( res =~ "^HTTP/1\.[01] 30[0-8]" ) {
      q = egrep( pattern:"^Location:.*", string:res, icase:TRUE );
      add_30x( url:page, port:port, host:host );

      # Don't echo back what we added ourselves...
      if( ! ( ( "?PageServices" >< page || "?D=A" >< page ) && ( "?PageServices" >< q || "?D=A" >< q ) ) ) {
        extract_location( data:res, port:port, host:host );
      }
      return NULL;
    }
  }

  if( egrep( pattern:"^Server:.*Apache.*", string:res, icase:TRUE ) ) {
    Apache = TRUE;
  } else if( egrep( pattern:"^Server:.*Netscape.*", string:res, icase:TRUE ) ) {
    iPlanet = TRUE;
  }

  if( ! egrep( pattern:"^Content-Type: text/(xml|html).*", string:res, icase:TRUE ) ) {
    return NULL;
  } else {
    res = strstr( res, string( "\r\n\r\n" ) );
    if( ! res ) return NULL; # Broken web server ?
    res = str_replace( string:res, find:string( "\r\n" ), replace:" " );
    res = str_replace( string:res, find:string( "\n" ), replace:" " );
    res = str_replace( string:res, find:string( "\t" ), replace:" " );
    return res;
  }
}

function token_split( content ) {

  local_var content, num, ret, len, i, j, k, str;

  num = 0;
  ret = make_list();
  len = strlen( content );

  for( i = 0; i < len; i++ ) {
    if( ( ( i + 3) < len ) && content[i] == "<" && content[i+1] == "!" && content[i+2] == "-" && content[i+3] == "-" ) {
      j = stridx( content, "-->", i );
      if( j < 0 ) return ret;
      i = j;
    } else {
      if( content[i] == "<" ) {
        str = "";
        i++;

        while( content[i] == " " ) i++;

        for( j = i; j < len; j++ ) {
          if( content[j] == '"' ) {
            k = stridx( content, '"', j + 1 );
            if( k < 0 ) {
              return ret; # bad page
            }
            str += substr( content, j, k );
            j = k;
          } else if( content[j] == '>' ) {
            if( ereg( pattern:"^(a|area|frame|meta|iframe|link|img|form|/form|input|button|textarea|select|applet|script)( .*|$)", string:str, icase:TRUE ) ) {
              num++;
              ret = make_list( ret, str );
              if( num > 500 ) return ret; # Too many items TBD: Previously was 50 which is clearly not enough for complex webpages
            }
            break;
          } else {
            str += content[j];
          }
        }
        i = j;
      }
    }
  }
  return ret;
}

function token_parse( token ) {

  local_var token, ret, len, current_word, word_index, i, j, current_value, char;

  ret = make_list();
  len = strlen( token );
  current_word = "";
  word_index = 0;

  for( i = 0; i < len; i++ ) {
    if( ( token[i] == " " ) || ( token[i] == "=" ) ) {
      while( i + 1 < len && token[i+1] == " " ) i++;
      if( i >= len ) break;

      if( word_index == 0 ) {
        ret["nasl_token_type"] = tolower( current_word );
      } else {
        while( i+1 < len && token[i] == " " ) i++;
        if( token[i] != "=" ) {
          ret[tolower(current_word)] = NULL;
        } else {
          i++;
          char = NULL;
          if( i >= len ) break;
          if( token[i] == '"' ) {
            char = '"';
          } else if( token[i] == "'" ) {
            char = "'";
          }

          if( ! isnull( char ) ) {
            j = stridx( token, char, i + 1 );
            if( j < 0 ) {
              if( debug ) display( "PARSE ERROR 1\n" );
              return ret; # Parse error
            }
            ret[tolower( current_word )] = substr( token, i + 1, j - 1 );
            while( j + 1 < len && token[j+1] == " " ) j++;
            i = j;
          } else {
            j = stridx( token, ' ', i + 1 );
            if( j < 0 ) {
              j = len;
            }
            ret[tolower( current_word )] = substr( token, i, j - 1 );
            i = j;
          }
        }
      }
      current_word = "";
      word_index++;
    } else {
      if( i < len ) current_word = current_word + token[i];
    }
  }

  if( ! word_index ) ret["nasl_token_type"] = tolower( current_word );

  return ret;
}

function parse_java( elements, port, host ) {

  local_var elements, port, host;
  local_var archive, code, codebase;

  archive = elements["archive"];
  code = elements["code"];
  codebase = elements["codebase"];

  if( codebase ) {
    if( archive ) {
      set_kb_item( name:"www/" + port + "/java_classfile", value:codebase + "/" + archive );
      set_kb_item( name:"www/" + host + "/" + port + "/java_classfile", value:codebase + "/" + archive );
    }
    if( code ) {
      set_kb_item( name:"www/" + port + "/java_classfile", value:codebase + "/" + code );
      set_kb_item( name:"www/" + host + "/" + port + "/java_classfile", value:codebase + "/" + code );
    }
  } else {
    if( archive ) {
      set_kb_item(name:"www/" + port + "/java_classfile", value:archive );
      set_kb_item(name:"www/" + host + "/" + port + "/java_classfile", value:archive );
    }
    if( code ) {
      set_kb_item(name:"www/" + port + "/java_classfile", value:archive );
      set_kb_item(name:"www/" + host + "/" + port + "/java_classfile", value:archive );
    }
  }
}

function parse_javascript( elements, current, port, host ) {

  local_var elements, current, port, host;
  local_var url, pat;

  if( debug > 15 ) display( "*** JAVASCRIPT\n" );

  pat = string( ".*window\\.open\\('([^',", raw_string(0x29), "]*)'.*\\)*" );
  url = ereg_replace( pattern:pat, string:elements["onclick"], replace:"\1", icase:TRUE );

  if( url == elements["onclick"] ) return NULL;

  url = canonical_url( url:url, current:current, port:port, host:host );
  if( url ) {
    add_url( url:url, port:port, host:host );
    return url;
  }
  return NULL;
}

function parse_dir_from_src( elements, current, port, host ) {

  local_var elements, current, port, host, src;

  src = elements["src"];
  if( ! src ) return NULL;

  src = canonical_url( url:src, current:current, port:port, host:host );

  add_cgi_dir( dir:src, port:port, host:host );
}

function parse_href_or_src( elements, current, port, host ) {

  local_var elements, current, port, host;
  local_var href;

  href = elements["href"];
  if( ! href ) href = elements["src"];

  if( ! href ) {
    return NULL;
  }

  href = canonical_url( url:href, current:current, port:port, host:host );
  if( href ) {
    add_url( url:href, port:port, host:host );
    return href;
  }
}

function parse_refresh( elements, current, port, host ) {

  local_var elements, current, port, host;
  local_var content, t, sub, href;

  if( elements["content"] == '0') return NULL;
  content = elements["content"];

  if( ! content ) return NULL;

  t = strstr( content, ";" );
  if( t != NULL ) content = substr( t, 1, strlen( t ) - 1 );

  content = string( "a ", content );
  sub = token_parse( token:content );

  if( isnull( sub ) ) return NULL;

  href = sub["url"];
  if( ! href ) return NULL;

  href = canonical_url( url:href, current:current, port:port, host:host );
  if( href ) {
    add_url( url:href, port:port, host:host );
    return href;
  }
}

function parse_form( elements, current, port, host ) {

  local_var elements, current, port, host;
  local_var action;

  action = elements["action"];

  # nb: <form action="" or <form action="#" resolves to the current URL
  if( ! isnull( action ) && ( action == "" || action == "#" ) ) action = current;

  action = canonical_url( url:action, current:current, port:port, host:host );
  if( action ) {
    return action;
  } else {
    return NULL;
  }
}

function pre_parse( src_page, data, port, host ) {

  local_var src_page, data, port, host;
  local_var js_data, data2, php_path, fp_save;

  if( js_data = eregmatch( string:data, pattern:'<script( type=(\'text/javascript\'|"text/javascript"|\'application/javascript\'|"application/javascript"))?>(.*)</script>', icase:TRUE ) ) {

    # https://coinhive.com/documentation/miner
    if( "CoinHive.Anonymous" >< js_data[3] || "CoinHive.User" >< js_data[3] || "CoinHive.Token" >< js_data[3] ) {
      set_kb_item( name:"www/coinhive/detected", value:TRUE );
      if( ! Misc[src_page] ) {
        # nb: The javascript might be embedded into web page by the owner on purpose.
        if( ".didOptOut" >< js_data[3] ) {
          set_kb_item( name:"www/" + port + "/content/coinhive_optout", value:report_vuln_url( port:port, url:src_page, url_only:TRUE ) );
          set_kb_item( name:"www/" + host + "/" + port + "/content/coinhive_optout", value:report_vuln_url( port:port, url:src_page, url_only:TRUE ) );
        # The "AuthedMine" (https://coinhive.com/documentation/authedmine) won't run the JS without asking the user.
        } else if( "https://authedmine.com/lib/authedmine.min.js" >< js_data[3] ) {
          set_kb_item( name:"www/" + port + "/content/coinhive_optin", value:report_vuln_url( port:port, url:src_page, url_only:TRUE ) );
          set_kb_item( name:"www/" + host + "/" + port + "/content/coinhive_optin", value:report_vuln_url( port:port, url:src_page, url_only:TRUE ) );
        } else {
          set_kb_item( name:"www/" + port + "/content/coinhive_nooptout", value:report_vuln_url( port:port, url:src_page, url_only:TRUE ) );
          set_kb_item( name:"www/" + host + "/" + port + "/content/coinhive_nooptout", value:report_vuln_url( port:port, url:src_page, url_only:TRUE ) );
        }
        Misc[src_page] = 1;
      }
    }

    # https://raw.githubusercontent.com/sizeofcat/malware-scripts/master/javascript/2-obfuscated.js
    # and the pages from https://badpackets.net/how-to-find-cryptojacking-malware/ have
    # this code in common.
    if( '();","\\x7C","\\x73\\x70\\x6C\\x69\\x74","' >< js_data[3] &&
        "\x43\x72\x79\x70\x74\x6F\x6E\x69\x67\x68\x74\x57\x41\x53\x4D\x57\x72\x61\x70\x70\x65\x72" >< js_data[3] ) {
      set_kb_item( name:"www/coinhive/detected", value:TRUE );
      if( ! Misc[src_page] ) {
        set_kb_item( name:"www/" + port + "/content/coinhive_obfuscated", value:report_vuln_url( port:port, url:src_page, url_only:TRUE ) );
        set_kb_item( name:"www/" + host + "/" + port + "/content/coinhive_obfuscated", value:report_vuln_url( port:port, url:src_page, url_only:TRUE ) );
        Misc[src_page] = 1;
      }
    }
  }

  if( "Index of /" >< data ) {
    if( ! Misc[src_page] ) {
      if( "?D=A" >!< src_page && "?PageServices" >!< src_page ) {
        set_kb_item( name:"www/" + port + "/content/dir_index", value:report_vuln_url( port:port, url:src_page, url_only:TRUE ) );
        set_kb_item( name:"www/" + host + "/" + port + "/content/dir_index", value:report_vuln_url( port:port, url:src_page, url_only:TRUE ) );
        Misc[src_page] = 1;
      }
    }
  }

  if( "<title>phpinfo()</title>" >< data ) {
    if( ! Misc[src_page] ) {
      set_kb_item( name:"www/" + port + "/content/phpinfo_script", value:report_vuln_url( port:port, url:src_page, url_only:TRUE ) );
      set_kb_item( name:"www/" + host + "/" + port + "/content/phpinfo_script", value:report_vuln_url( port:port, url:src_page, url_only:TRUE ) );
      Misc[src_page] = 1;
    }
  }

  if( "Fatal" >< data || "Warning" >< data ) {

    data2 = strstr( data, "Fatal" );
    if( ! data2 ) data2 = strstr( data, "Warning" );

    data2 = strstr( data2, "in <b>" );

    php_path = ereg_replace( pattern:"in <b>([^<]*)</b>.*", string:data2, replace:"\1" );
    if( php_path != data2 ) {
      if( ! Misc[src_page] ) {
        set_kb_item( name:"www/" + port + "/content/php_physical_path", value:report_vuln_url( port:port, url:src_page, url_only:TRUE ) + " (" + php_path + ")" );
        set_kb_item( name:"www/" + host + "/" + port + "/content/php_physical_path", value:report_vuln_url( port:port, url:src_page, url_only:TRUE ) + " (" + php_path + ")" );
        Misc[src_page] = 1;
      }
    }
  }

  data2 = strstr( data, "unescape" );

  if( data2 && ereg( pattern:"unescape..(%([0-9]|[A-Z])*){200,}.*", string:data2 ) ) {
    if( ! Misc[src_page] ) {
      set_kb_item( name:"www/" + port + "/content/guardian", value:report_vuln_url( port:port, url:src_page, url_only:TRUE ) );
      set_kb_item( name:"www/" + host + "/" + port + "/content/guardian", value:report_vuln_url( port:port, url:src_page, url_only:TRUE ) );
      Misc[src_page] = 1;
    }
  }

  if( "CREATED WITH THE APPLET PASSWORD WIZARD WWW.COFFEECUP.COM" >< data ) {
    if( ! Misc[src_page] ) {
      set_kb_item( name:"www/" + port + "/content/coffeecup", value:report_vuln_url( port:port, url:src_page, url_only:TRUE ) );
      set_kb_item( name:"www/" + host + "/" + port + "/content/coffeecup", value:report_vuln_url( port:port, url:src_page, url_only:TRUE ) );
      Misc[src_page] = 1;
    }
  }

  if( "SaveResults" >< data ) {
    fp_save = ereg_replace( pattern:'(.*SaveResults.*U-File=)"(.*)".*', string:data, replace:"\2" );
    if( fp_save != data ) {
      if( ! Misc[src_page] ) {
        set_kb_item( name:"www/" + port + "/content/frontpage_results", value:report_vuln_url( port:port, url:src_page, url_only:TRUE ) + " (" + fp_save + ")" );
        set_kb_item( name:"www/" + host + "/" + port + "/content/frontpage_results", value:report_vuln_url( port:port, url:src_page, url_only:TRUE ) + " (" + fp_save + ")" );
        Misc[src_page] = 1;
      }
    }
  }
}

function parse_main( current, data, port, host ) {

  local_var current, data, port, host;
  local_var form_cgis, form_cgis_level, argz, store_cgi, token, tokens, elements, cgi;

  form_cgis = make_list();
  form_cgis_level = 0;
  argz = NULL;
  store_cgi = 0;
  tokens = token_split( content:data );

  foreach token( tokens ) {

    elements = token_parse( token:token );
    if( ! isnull( elements ) ) {
      if( elements["onclick"] ) {
        parse_javascript( elements:elements, current:current, port:port, host:host );
      }

      if( elements["nasl_token_type"] == "applet" ) {
        parse_java( elements:elements, port:port, host:host );
      }

      if( elements["nasl_token_type"] == "a" ||
          elements["nasl_token_type"] == "link" ||
          elements["nasl_token_type"] == "frame" ||
          elements["nasl_token_type"] == "iframe" ||
          elements["nasl_token_type"] == "area" ) {

        if( parse_href_or_src( elements:elements, current:current, port:port, host:host ) == NULL ) {
          if( debug > 20 ) display( "ERROR - ", token, "\n" );
        }
      }

      if( elements["nasl_token_type"] == "img" ||
          elements["nasl_token_type"] == "script" ) {
        parse_dir_from_src( elements:elements, current:current, port:port, host:host );
      }

      if( elements["nasl_token_type"] == "meta" ) {
        parse_refresh( elements:elements, current:current, port:port, host:host );
      }

      if( elements["nasl_token_type"] == "form" ) {
        cgi = parse_form( elements:elements, current:current, port:port, host:host );
        if( cgi ) {
          form_cgis[form_cgis_level] = cgi;
          store_cgi = 1;
        }
        form_cgis_level++;
      }

      if( elements["nasl_token_type"] == "/form" ) {
        form_cgis_level--;
        # Resetting the count to 0 if we're getting a negative value here.
        # Most likely something is broken on this page (opened <form> without a closing </form>).
        # Without this a "Negative integer index are not supported yet!" is thrown here.
        if( form_cgis_level < 0 ) form_cgis_level = 0;
        if( store_cgi != 0 ) add_cgi( cgi:form_cgis[form_cgis_level], args:argz, port:port, host:host );
        argz = "";
        store_cgi = 0;
      }

      if( elements["nasl_token_type"] == "input" ||
          elements["nasl_token_type"] == "select" ) {
        if( elements["name"] ) {
          argz += string( elements["name"], " [", elements["value"], "] " );
        }
        if( elements["name"] && elements["type"] == "password" ) {
          # nb: We just want to report one input field for each page
          # There might be some pages having more then one but this is
          # quite uncommon and the solution is to switch to HTTPs anyway...
          if( ! PW_inputs[current] ) {
            PW_inputs[current] = 1;
            set_kb_item( name:"www/pw_input_field/detected", value:TRUE );
            set_kb_item( name:"www/pw_input_field_or_basic_auth/detected", value:TRUE );
            # Used in 2018/gb_http_cleartext_creds_submit.nasl
            set_kb_item( name:"www/" + port + "/content/pw_input_field/" + current, value:report_vuln_url( port:port, url:current, url_only:TRUE ) + ":" + elements['name'] );
            set_kb_item( name:"www/" + host + "/" + port + "/content/pw_input_field/" + current, value:report_vuln_url( port:port, url:current, url_only:TRUE ) + ":" + elements['name'] );
          }
        }
      }
    }
  }
}

#----------------------------------------------------------------------#
#                                MAIN()                                #
#----------------------------------------------------------------------#
port = get_http_port( default:80 );
host = http_host_name( dont_add_port:TRUE );

dirs = cgi_dirs( port:port, host:host );

if( dirs ) {
  URLs_start = make_list_unique( start_page, dirs );
} else {
  URLs_start = make_list( start_page );
}

# From DDI_Directory_Scanner.nasl
redirects = get_kb_list( "DDI_Directory_Scanner/" + host + "/" + port + "/received_redirects" );

if( redirects )
  URLs_start = make_list( URLs_start, redirects );

# Test for servers which return 401 for everything
req = http_get( item:"/NonExistent" + rand() + "/", port:port );
res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( res =~ "^HTTP/1\.[01] 401" ) {
  if( debug ) display( "*** This server requires authentication for non-existent directories, disabling 401 checks.\n" );
  Check401 = FALSE;
}

URLs = URLs_start;

# We can't modify the URLs list below from within the foreach loop
# to add additional detected URLs since GVM-10 so we need to handle
# it differently
while( TRUE ) {

  foreach URL( URLs ) {
    if( ! URLs_hash[URL] ) {

      if( cgi_dirs_exclude_servermanual ) {

        # Ignore Apache2 manual if it exists. This is just huge static content
        # and slows down the scanning without any real benefit.
        if( URL =~ "^/manual" ) {
          res = http_get_cache( item:"/manual/en/index.html", port:port );
          if( "Documentation - Apache HTTP Server" >< res ) {
            URLs_hash[URL] = 1;
            set_kb_item( name:"www/" + port + "/content/servermanual_directories", value:report_vuln_url( port:port, url:URL, url_only:TRUE ) + ", Content: Apache HTTP Server Manual" );
            set_kb_item( name:"www/" + host + "/" + port + "/content/servermanual_directories", value:report_vuln_url( port:port, url:URL, url_only:TRUE ) + ", Content: Apache HTTP Server Manual" );
            continue;
          }
        }

        # Similar to the above for Tomcat
        if( URL =~ "^/tomcat-docs" ) {
          res = http_get_cache( item:"/tomcat-docs/", port:port );
          if( "Apache Tomcat" >< res && "Documentation Index" >< res ) {
            URLs_hash[URL] = 1;
            set_kb_item( name:"www/" + port + "/content/servermanual_directories", value:report_vuln_url( port:port, url:URL, url_only:TRUE ) + ", Content: Apache Tomcat Documentation" );
            set_kb_item( name:"www/" + host + "/" + port + "/content/servermanual_directories", value:report_vuln_url( port:port, url:URL, url_only:TRUE ) + ", Content: Apache Tomcat Documentation" );
            continue;
          }
        }
      }

      page = retr( port:port, page:URL, host:host );
      cnt++;
      pre_parse( src_page:URL, data:page, port:port, host:host );
      parse_main( data:page, current:URL, port:port, host:host );
      URLs_hash[URL] = 1;
      if( cnt >= max_pages ) {
        if( debug ) display( "*** Max pages ", max_pages, " reached, stopping test.\n" );
        set_kb_item( name:"www/" + port + "/content/max_pages_reached", value:TRUE );
        set_kb_item( name:"www/" + host + "/" + port + "/content/max_pages_reached", value:TRUE );
        break;
      }
    }
  }

  if( max_index( URLs_discovered ) > 0 ) {
    # nb: Set the discovered URLs into the list for the next iteration
    URLs = URLs_discovered;
    # And reset the discovered list
    URLs_discovered = make_list();
  } else {
    break;
  }
}

if( cnt == 1 ) {
  if( RootPasswordProtected ) {
    set_kb_item( name:"www/" + port + "/password_protected", value:TRUE );
    set_kb_item( name:"www/" + host + "/" + port + "/password_protected", value:TRUE );
  }
}

exit( 0 );
