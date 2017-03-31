###############################################################################
# $Id: sharp_printers.inc 4108 2016-09-19 10:34:25Z cfi $
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
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
#
# $Revision: 4108 $
#
###############################################################################

sharp_detect_urls = make_array();

# URL                                   # Regex
sharp_detect_urls['/'] = '<title>(MX-M260N|AR-M155|AR-M450U|AR-M550U|MX-M700N|MX-M620N|AR-M351U|AR-M451U|MX-M550N|AR-M700U|AR-M276|MX-M310N|AR-168D|AR-M236|MX-M450U|AR-M237|MX-M350N|MX-M550U|AR-M160|AL-2051|AL-2061|MX-B201D)</title>';
sharp_detect_urls['/login.html?/main.html'] = '<title>.* - ([^<]+)</title>';
sharp_detect_urls['/link.html'] = '>(AR-M350|im3511|im4512)<';

function sharp_default_logins() {

  return make_list("admin:Sharp","admin:1234","Administrator:admin","administrator:admin","admin:admin","admin:00000");
}

function check_sharp_default_login(model) {

  local_var userame, password, sharp;
  global_var last_user, last_pass;

  sharp = sharp_login_details(model:model);
  if(!sharp) return FALSE;

  logins = sharp_default_logins();

  foreach login (logins) {

    user_pass = split(login,sep:":", keep:FALSE);
    username = user_pass[0];
    password = user_pass[1];

    login_data = sharp['login_data'];
    if(login_data) {
      login_data = str_replace(string:login_data, find:"%%%USERNAME%%%", replace:username);
      login_data = str_replace(string:login_data, find:"%%%PASSWORD%%%", replace:password);
    }

    len = strlen(login_data);

    if(sharp['req_type'] == "POST") {

      if(sharp['login_url_success']) {
        req = string(sharp['req_type_success'], " ", sharp['login_url_success'], " HTTP/1.1\r\n",
                     "Host: ", get_host_name(),"\r\n",
                     "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:17.0) Gecko/17.0 Firefox/17.0\r\n\r\n");

        buf = http_send_recv(port:port, data:req, bodyonly:FALSE);
        sharp_error_exit(buf:buf);

        if(eregmatch(pattern:sharp['login_success'], string:buf)) {
          return 2; # setup without auth
        }

      }

      req = string("POST " , sharp['login_url'], " HTTP/1.1\r\n",
                   "Host: ", get_host_name(),"\r\n",
                   "DNT: 1\r\n",
                   "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:17.0) Gecko/17.0 Firefox/17.0\r\n",
                   "Content-Type: application/x-www-form-urlencoded\r\n",
                   "Content-Length: ",len,"\r\n");

      if(cookie) req +=  string("Cookie: ",cookie,"\r\n");

      req += string("\r\n",login_data,"\r\n");

    }

    else if(sharp['req_type'] == "GET") {

      if(sharp['req_auth'] == "BASIC") {

        userpass = username + ':' + password;
        userpass64 = base64(str:userpass);

        req = string("GET ", sharp['login_url']," HTTP/1.1\r\n",
                     "Host: ", get_host_name(),"\r\n");

        c_buf = http_send_recv(port:port, data:req + '\r\n', bodyonly:FALSE);
        sharp_error_exit(buf:c_buf);

        if(c_buf !~ "HTTP/1.. 401" && "HTTP/1.1 302" >!< c_buf) return 2; # setup without auth

        req += string("Authorization: Basic ",userpass64,"\r\n\r\n");

      }

    } else {
      return FALSE;
    }

    buf = http_send_recv(port:port, data:req, bodyonly:FALSE); # login

    if(ereg(pattern:sharp['http_status'], string:buf)) {

      update_cookie(buf:buf);

      if(sharp['login_url_success']) {

        req = string(sharp['req_type_success'], " ", sharp['login_url_success'], " HTTP/1.1\r\n",
                    "Host: ", get_host_name(),"\r\n");

        if(cookie) req +=  string("Cookie: ",cookie,"\r\n");

        req += string("User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:17.0) Gecko/17.0 OpenVAS\r\n\r\n");

        buf = http_send_recv(port:port, data:req, bodyonly:FALSE);
        sharp_error_exit(buf:buf);

      }

      if(eregmatch(pattern:sharp['login_success'], string:buf)) {
        last_user = username;
        last_pass = password;
        return 1;
      }

    }
  }

  return FALSE;

}

function sharp_login_details(model) {

  global_var cookie;

  sharp = make_array();

  if(model == "MX-4100N"  ||
     model == "MX-M453U"  ||
     model == "MX-5001N"  ||
     model == "MX-2700FG" ||
     model == "MX-2310U"  ||
     model == "MX-2301N"  ||
     model == "MX-M453N"  ||
     model == "MX-6200N"  ||
     model == "MX-4111N"  ||
     model == "MX-M452N"  ||
     model == "MX-M362N"  ||
     model == "MX-2614N"  ||
     model == "MX-M453U"  ||
     model == "MX-M453N"  ||
     model == "MX-M453"   ||
     model == "MX-7001N"  ||
     model == "MX-2010U"  ||
     model == "MX-M363N"  ||
     model == "MX-M363U"  ||
     model == "MX-M363"   ||
     model == "MX-M363N"  ||
     model == "MX-3110N"  ||
     model == "MX-2600N"  ||
     model == "MX-4501N"  ||
     model == "MX-6240N"  ||
     model == "MX-M283N"  ||
     model == "MX-M354N"  ||
     model == "MX-C311"   ||
     model == "MX-M502N"  ||
     model == "MX-2300N"  ||
     model == "MX-M503N"  ||
     model == "MX-B402SC") {

    if(!cookie) sharp_set_cookie(url:'/main.html');

    sharp['req_type'] = "POST";
    sharp['login_url'] = '/login.html?/main.html';
    sharp['login_data'] = 'ggt_select%2810009%29=3&ggt_textbox%2810003%29=%%%PASSWORD%%%&action=loginbtn&ggt_hidden%2810008%29=4';

    sharp['req_type_success'] = "GET";
    sharp['login_url_success'] = '/main.html';

    sharp['http_status'] = 'HTTP/1.. 302';
    sharp['login_success'] = '<!--Logoff \\(L\\)-->';

    return sharp;

  }

  else if(model == "MX-B201D" ||
          model == "AL-2051"  ||
          model == "AL-2061"  ||
          model == "AR-M160"  ||
          model == "AR-M236"  ||
          model == "MX-M450U" ||
          model == "AR-M237"  ||
          model == "MX-M620N" ||
          model == "MX-M350N" ||
          model == "MX-M550U" ||
          model == "MX-M310N" ||
          model == "MX-M700N" ||
          model == "AR-168D"  ||
          model == "AR-M700U" ||
          model == "MX-M550N" ||
          model == "AR-M451U" ||
          model == "AR-M351U" ||
          model == "AR-M550U" ||
          model == "AR-M450U" ||
          model == "AR-M155"  ||
          model == "MX-M260N" ||
          model == "AR-M350"  ||
          model == "im3511"   ||
          model == "im4512"   ||
          model == "AR-M276") {

    sharp['req_type'] = "GET";
    sharp['login_url'] = '/password.html';
    sharp['req_auth'] = "BASIC";

    sharp['http_status'] = 'HTTP/1.. 200';
    sharp['login_success'] = '<title>Password Setup Page';

    return sharp;

  }

  exit(0); # we don't know this printer

}

function build_sharp_cpe(model) {


  model = tolower(model);

  if(model == "") return 'cpe:/h:sharp';

  return 'cpe:/h:sharp:' + model;

}

function sharp_set_cookie(url) {

  global_var cookie;

  req = http_get(item:url, port:port);
  buf = http_send_recv(port:port, data:req, bodyonly:FALSE);

  if("Set-Cookie:" >!< buf) return FALSE;

  co = eregmatch(pattern:"Set-Cookie: ([^; ]+)", string:buf);
  if(!isnull(co[1])) {
    cookie = co[1];
    return TRUE;
  }

  return FALSE;

}

function update_cookie(buf) {

  global_var cookie;

  if("Set-Cookie:" >!< buf) return FALSE;

  co = eregmatch(pattern:"Set-Cookie: ([^; ]+)", string:buf);
  if(!isnull(co[1])) {
    cookie = co[1];
    return TRUE;
  }

  return FALSE;

}

function sharp_error_exit(buf) {

  if(!buf || ereg(pattern:"HTTP/1.(0|1) (404|500)", string: buf))exit(0);

  return TRUE;

}
