# OpenVAS Vulnerability Test
# $Id: http_login.nasl 8023 2017-12-07 08:36:26Z teissa $
# Description: HTTP login page
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
#
# Copyright:
# Copyright (C) 2002 Michel Arboi
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

tag_summary = "This script logs onto a web server through a login page and
stores the authentication / session cookie.";

if(description)
{
 script_id(11149);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 8023 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-07 09:36:26 +0100 (Thu, 07 Dec 2017) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"0.0");
 
 name = "HTTP login page";
 script_name(name);
  
 
 script_category(ACT_GATHER_INFO); # Has to run after find_service
 script_tag(name:"qod_type", value:"remote_banner");
 
 script_copyright("This script is Copyright (C) 2002 Michel Arboi");
 family = "Settings";
 script_family(family);

 # We first visit this page to get a cookie, just in case
 script_add_preference(name:"Login page :", type: "entry", value: "/");
 # Then we submit the username & password to the right form
 script_add_preference(name:"Login form :", type: "entry", value: "");
 # Here, we allow some kind of variable substitution. 
 script_add_preference(name:"Login form fields :", type: "entry", 
	value:"user=%USER%&pass=%PASS%");
 script_dependencies("httpver.nasl", "logins.nasl");
 script_require_ports("Services/www", 80);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");

# The script code starts here

http_login = get_kb_item("http/login");
http_pass = get_kb_item("http/password");
http_login_form = script_get_preference("Login form :");
http_login_page = script_get_preference("Login page :");
http_login_fields = script_get_preference("Login form fields :");

if (! http_login_form) exit(0);
if (! http_login_fields) exit(0);

if (http_login)
{
  http_login_fields = ereg_replace(string: http_login_fields,
	pattern: "%USER%", replace: http_login);
}
if (http_pass)
{
  http_login_fields = ereg_replace(string: http_login_fields,
	pattern: "%PASS%", replace: http_pass);
}

port = get_http_port(default:80);

if(! get_port_state(port)) exit(0);

soc = http_open_socket(port);
if (! soc) exit(0);

cookie1="";
referer="";
if (http_login_page)
{
  req = http_get(port: port, item: http_login_page);
  send(socket: soc, data: req);
  r = http_recv_headers2(socket:soc);
  #r2 = recv(socket: soc, length: 1024);
  close(soc);
  soc = http_open_socket(port);
  if (! soc) exit(0);
  cookies = egrep(pattern: "Set-Cookie2? *:", string: r);
  if (cookies)
  {
    cookie1 = ereg_replace(string: cookies, 
		pattern: "^Set-Cookie", replace: "Cookie");
    c = ereg_replace(string: cookie1, 
	pattern: "^Cookie2? *: *", replace: "");
    #display("First cookie = ", c);
  }
  trp = get_port_transport(port);
  if (trp > ENCAPS_IP) referer = "Referer: https://";
  else referer = "Referer: http://";
  referer = string(referer, get_host_name());
  if (((trp == 1) && (port != 80)) || ((trp > 1) && (port != 443)))
    referer = string(referer, ":", port);
  if (ereg(pattern: "^[^/]", string: http_login_page))
    referer = string(referer, "/");
  referer = string(referer, http_login_page, "\r\n");
}


req = http_post(port: port, item: http_login_form, data: http_login_fields);
req = ereg_replace(string: req, pattern: "Content-Length: ",
	replace: string("Content-Type: application/x-www-form-urlencoded\r\n",
			referer, cookie1, "Content-Length: ") );
send(socket:soc, data:req);
r = http_recv_headers2(socket:soc);
close(soc);

h = split(r);

foreach r (h) {
  # Failed - permission denied or bad gateway or whatever
  if (egrep(pattern: "HTTP/[019.]+ +[45][0-9][0-9]", string: r)) exit(0);

  if (r =~ "^Set-Cookie")
{
  if(!first_cookie) {
    cookies_string += ereg_replace(string: r, pattern: "^Set-Cookie", replace: "Cookie");
    cookies_string = chomp(cookies_string);
    first_cookie = TRUE;
  } else {
    cookies_string += ereg_replace(string: r, pattern: "^Set-Cookie:", replace: ";");
    cookies_string = chomp(cookies_string);
  }

  # set_kb_item(name: string("/tmp/http/auth/", port), value: cookies);
  ##set_kb_item(name: "http/auth", value: cookies);
  c = ereg_replace(string: cookies, 
        pattern: "^Cookie2? *: *", replace: "");
  #  display("Authentication cookie = ", c);
  }
  else if (cookie1)
  {
    set_kb_item(name: string("/tmp/http/auth/", port), value: cookie1);
  # display("Trying to use session cookie\n");
  }

}

if(cookies_string) {
  set_kb_item(name: string("/tmp/http/auth/", port), value:  cookies_string);
}

