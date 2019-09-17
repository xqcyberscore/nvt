###############################################################################
# OpenVAS Include File
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH
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

# @brief Returns an array containing the URL for a Lexmark printer detection
#        as the array key and the regex to extract the type/model as the value.
#
# @note The array key might contain a pattern like e.g. (numbers incrementing
#       for multiple same URLs):
#
#       #--avoid-dup1--#
#
#       to be able to have different array keys for the same URL.
#       Make sure to strip such patterns away with ereg_replace
#       in the VT calling this function.
#
# @return An array as described in the function description.
#
function get_lexmark_detect_urls() {

  local_var lexmark_detect_urls;

  lexmark_detect_urls = make_array();

  lexmark_detect_urls['/']                 = '<title>Lexmark ([^<]+)</title>';
  lexmark_detect_urls['/#--avoid-dup1--#'] = '<title>Lexmark&#032;([^<]+)</title>';

  return lexmark_detect_urls;
}


# @brief Checks for default/no authentication at Lexmark printers
#
# @param model The model name of the printer
#
# @param port  The port to check
#
# @return 2 in case of successful authentication, TRUE in case of authentication error and FALSE in case of
#         an error (e.g. no model details found) 
#
function check_lexmark_default_login( model, port ) {

  local_var model, port, lex, host, req, buf;

  lex = lexmark_login_details( model:model );
  if( ! lex ) return FALSE;

  if( lex['no_default_auth'] ) {
    if( lex['req_type'] == "GET" ) {
      if( lex['req_auth'] == "BASIC" ) {

        if( lex['headers'] ) {

          req = http_get_req( port:port, url:lex['login_url'], add_headers:lex['headers'] );
          buf = http_send_recv( port:port, data:req, bodyonly:FALSE );
        } else {

          req = http_get( port:port, item:lex['login_url'] );
          buf = http_send_recv( port:port, data:req, bodyonly:FALSE );
        }

        lexmark_error_exit( buf:buf );

        if( ereg( pattern:lex['http_status'], string:buf ) ) {
          if( eregmatch( pattern:lex['login_success'], string:buf ) ) {
            return 2;
          }
        }
      }
    }
  }
}

# @brief Returns an array with the details about the login/restricted pages to check authentication for depending
#        on the model provided
#
# @param model The model to return the details for
#
# @return An array containing the needed information for authentication checks
#
#         ret_array["req_type"]        = the request type (GET/POST)
#         ret_array["login_url"]       = the url to check authentication
#         ret_array["req_auth"]        = the kind of authentication (currently BASIC)
#         ret_array["no_default_auth"] = boolean if default no authentication is set
#         ret_array["headers"]         = HTTP headers to add to the request as an array (optional)
#         ret_array["http_status"]     = the HTTP status to expect from a successful authentication as a regex
#         ret_array["login_success"]   = regex to check for in case of successful authentication
#
function lexmark_login_details( model ) {

  local_var model, lexmark_printer;

  lexmark_printer = make_array();

  if(model == "CS421dn"   ||
          model == "CS622de"   ||
          model == "CS923de"   ||
          model == "CX421adn"  ||
          model == "CX522ade"  ||
          model == "CX622ade"  ||
          model == "MS321dn"   ||
          model == "MS421dn"   ||
          model == "MS521dn"   ||
          model == "MS621dn"   ||
          model == "MS821n"    ||
          model == "MS821dn"   ||
          model == "MS823n"    ||
          model == "MS823dn"   ||
          model == "MS826de"   ||
          model == "MX321adn"  ||
          model == "MX421ade"  ||
          model == "MX622adhe" ||
          model == "XC8160") {

    lexmark_printer['req_type']  = "GET";
    lexmark_printer['login_url'] = '/webglue/content?c=%2FSettings%2FSecurity%2FEditSecuritySetups%2FInternalAccounts%2FManageInternalGroups&lang=en';
    lexmark_printer['req_auth']  = "BASIC";
    lexmark_printer['no_default_auth'] = "TRUE";
    lexmark_printer['headers'] = make_array("X-Requested-With", "XMLHttpRequest");

    lexmark_printer['http_status'] = 'HTTP/1.. 200';
    lexmark_printer['login_success'] = '\nAdd Group\n';

    return lexmark_printer;
  }

  else if(model == "T644"   ||
     model == "E450dn" ||
     model == "T642"   ||
     model == "119") {

    lexmark_printer['req_type']  = "GET";
    lexmark_printer['login_url'] = '/cgi-bin/dynamic/config/secure/changepass.html';
    lexmark_printer['req_auth']  = "BASIC";
    lexmark_printer['no_default_auth'] = "TRUE";

    lexmark_printer['http_status'] = 'HTTP/1.. 200';
    lexmark_printer['login_success'] = 'NAME="vac.255.GENPASSWORD"';

    return lexmark_printer;
  }

  else if(model == "T630" ||
          model == "C510" ||
          model == "T620" ||
          model == "T522" ||
          model == "T520") {

    lexmark_printer['req_type']  = "GET";
    lexmark_printer['login_url'] = '/port_0/config/security';
    lexmark_printer['req_auth']  = "BASIC";
    lexmark_printer['no_default_auth'] = "TRUE";

    lexmark_printer['http_status'] = 'HTTP/1.. 200';
    lexmark_printer['login_success'] = 'NAME="GENPASSWORD"';

    return lexmark_printer;
  }

  else if(model == "X954"    ||
          model == "X952"    ||
          model == "X656de"  ||
          model == "X792"    ||
          model == "T650"    ||
          model == "X464de"  ||
          model == "C925"    ||
          model == "X463de"  ||
          model == "C734"    ||
          model == "E460dn"  ||
          model == "E462dtn" ||
          model == "T652"    ||
          model == "C792"    ||
          model == "MX410de" ||
          model == "MX910de" ||
          model == "T654"    ||
          model == "C925"    ||
          model == "X746"    ||
          model == "C736"    ||
          model == "X738de"  ||
          model == "X864de")  {

    lexmark_printer['req_type']  = "GET";
    lexmark_printer['login_url'] = '/cgi-bin/dynamic/printer/config/secure/authsetup.html';
    lexmark_printer['req_auth']  = "BASIC";
    lexmark_printer['no_default_auth'] = "TRUE";

    lexmark_printer['http_status'] = 'HTTP/1.. 200';
    lexmark_printer['login_success'] = 'select name="auth_type" id="auth_type"';

    return lexmark_printer;
  }

  else if(model == "CS310dn"  ||
          model == "CS317dn"  ||
          model == "CS410dn"  ||
          model == "CX310dn"  ||
          model == "CX317dn"  ||
          model == "CX410de"  ||
          model == "CX417de"  ||
          model == "CX510de"  ||
          model == "CX517de"  ||
          model == "MX310dn"  ||
          model == "MX317dn"  ||
          model == "MX410de"  ||
          model == "MX417de"  ||
          model == "MX510de"  ||
          model == "MX511de"  ||
          model == "MX517de"  ||
          model == "MX611de"  ||
          model == "MX617de"  ||
          model == "X860de"   ||
          model == "X864de"   ||
          model == "X950"     ||
          model == "x954"     ||
          model == "XC2132"   ||
          model == "XM1145"   ||
          model == "XM3150"   ||
          model == "XM5170"   ||
          model == "XM7155"   ||
          model == "XM7170") {

    lexmark_printer['req_type']  = "GET";
    lexmark_printer['login_url'] = '/cgi-bin/dynamic/config/gen/changepass.html';
    lexmark_printer['req_auth']  = "BASIC";
    lexmark_printer['no_default_auth'] = "TRUE";

    lexmark_printer['http_status'] = 'HTTP/1.. 200';
    lexmark_printer['login_success'] = ': 8( | )?-( )?128 ';

    return lexmark_printer;
  }

  else if(model == "E260dn"         ||
          model == "X342n"          ||
          model == "X203n"          ||
          model == "X204n"          ||
          model == "C543"           ||
          model == "X364dn"         ||
          model == "E250dn"         ||
          model == "X264dn"         ||
          model == "S510 Series"    ||
          model == "C544"           ||
          model == "Pro5500 Series" ||
          model == "E360dn"         ||
          model == "X543"           ||
          model == "S310 Series"    ||
          model == "X544"           ||
          model == "C540") {

    lexmark_printer['req_type']  = "GET";
    lexmark_printer['login_url'] = '/cgi-bin/dynamic/config/gen/changepass.html';
    lexmark_printer['req_auth']  = "BASIC";
    lexmark_printer['no_default_auth'] = "TRUE";

    lexmark_printer['http_status'] = 'HTTP/1.. 200';
    lexmark_printer['login_success'] = 'NAME="vac.255.GENPASSWORD"';

    return lexmark_printer;
  }

  else if(model == "C935"  ||
          model == "X642e" ||
          model == "C782"  ||
          model == "X945e") {

    lexmark_printer['req_type']  = "GET";
    lexmark_printer['login_url'] = '/cgi-bin/dynamicpf/pf/config/gen/changepass.html';
    lexmark_printer['req_auth']  = "BASIC";
    lexmark_printer['no_default_auth'] = "TRUE";

    lexmark_printer['http_status'] = 'HTTP/1.. 200';
    lexmark_printer['login_success'] = 'NAME="vac.255.GENPASSWORD"';

    return lexmark_printer;
  }

  else if(model == "T656") {

    lexmark_printer['req_type']  = "GET";
    lexmark_printer['login_url'] = '/cgi-bin/dynamic/printer/config/secure/auth/backuppwd.html';
    lexmark_printer['req_auth']  = "BASIC";
    lexmark_printer['no_default_auth'] = "TRUE";

    lexmark_printer['http_status'] = 'HTTP/1.. 200';
    lexmark_printer['login_success'] = 'id="useFallbackPassword"';

    return lexmark_printer;
  }
}

# @brief Helper function to check for error status received
#
# @param buf HTTP response from printer
#
# @return TRUE if no error occurred, exit with code 0 in case of an error received
#
function lexmark_error_exit( buf ) {

  local_var buf;

  if( ! buf || ereg( pattern:"HTTP/1.(0|1) (404|401|500)", string:buf ) ) exit( 0 );
  return TRUE;
}
