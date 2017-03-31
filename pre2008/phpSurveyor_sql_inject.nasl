# OpenVAS Vulnerability Test
# $Id: phpSurveyor_sql_inject.nasl 3398 2016-05-30 07:58:00Z antu123 $
# Description: PHPSurveyor sid SQL Injection Flaw
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
#
# Copyright:
# Copyright (C) 2006 David Maciejak
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

tag_summary = "The remote web server contains a PHP script that is affected by a SQL
injection flaw. 

Description:

The remote host is running PHPSurveyor, a set of PHP scripts that
interact with MySQL to develop surveys, publish surveys and collect
responses to surveys. 

The remote version of this software is prone to a SQL injection flaw. 
Using specially crafted requests, an attacker can manipulate database
queries on the remote system.";

tag_solution = "Upgrade to PHPSurveyor version 0.991 or later.";

# Ref: taqua

if(description)
{
 script_id(20376);
 script_version("$Revision: 3398 $");
 script_tag(name:"last_modification", value:"$Date: 2016-05-30 09:58:00 +0200 (Mon, 30 May 2016) $");
 script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

 script_cve_id("CVE-2005-4586");
 script_bugtraq_id(16077);
 script_xref(name:"OSVDB", value:"22039");
  
 name = "PHPSurveyor sid SQL Injection Flaw";
 script_name(name);
 
 summary = "Checks for PHPSurveyor sid SQL injection flaw";
 
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_active");
  
 script_copyright("This script is Copyright (C) 2006 David Maciejak");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("http_version.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 script_xref(name : "URL" , value : "http://www.phpsurveyor.org/mantis/view.php?id=286");
 script_xref(name : "URL" , value : "http://sourceforge.net/project/shownotes.php?release_id=381050&group_id=74605");
 exit(0);
}

#
# the code
#

 include("global_settings.inc");
 include("http_func.inc");
 include("http_keepalive.inc");

 port = get_http_port(default:80);
 if(!get_port_state(port))exit(0);
 if (!can_host_php(port:port) ) exit(0);

 # Check a few directories.
 dirs = make_list("/phpsurveyor", "/survey", cgi_dirs());

 foreach dir (dirs)
 { 
  req = http_get(item:string(dir,"/admin/admin.php?sid=0'"),port:port);
  r = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

  if(egrep(pattern:"mysql_num_rows(): supplied argument is not a valid MySQL .+/admin/html.php", string:r))
  {
    security_message(port);
    exit(0);
  }
 }
