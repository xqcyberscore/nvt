# OpenVAS Vulnerability Test
# $Id: knowledge_builder_code_execution.nasl 6056 2017-05-02 09:02:50Z teissa $
# Description: Remote Code Execution in Knowledge Builder
#
# Authors:
# Noam Rathaus
#
# Copyright:
# Copyright (C) 2003 Noam Rathaus
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

# From: Zero_X www.lobnan.de Team [zero-x@linuxmail.org]
# Subject: Remote Code Execution in Knowledge Builder
# Date: Wednesday 24/12/2003 15:45

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11959");
  script_version("$Revision: 6056 $");
  script_tag(name:"last_modification", value:"$Date: 2017-05-02 11:02:50 +0200 (Tue, 02 May 2017) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Remote Code Execution in Knowledge Builder");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2003 Noam Rathaus");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name : "solution" , value : "Upgrade to the latest version or disable this CGI altogether");
  script_tag(name : "summary" , value : "KnowledgeBuilder is a feature-packed knowledge base solution CGI suite. 

  A vulnerability in this product may allow a remote attacker to execute 
  arbitrary commands on this host.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if (! can_host_php(port:port) ) exit(0);

function check_dir(path)
{

 if(path == "/") path = "";

 req = http_get(item:string(path, "/index.php?page=http://xxxxxxxxxxxxx/openvas"), port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if ( res == NULL ) exit(0);
 find = string("operation error");
 find_alt = string("getaddrinfo failed");

 if (find >< res || find_alt >< res )
 {
  req = http_get(item:string(path, "/index.php?page=index.php"), port:port);
  res = http_keepalive_send_recv(port:port, data:req);
  if ( res == NULL ) exit(0);
  if ( find >< res || find_alt >< res ) exit(0);
  security_message(port:port);
  exit(0);
 }
}

foreach dir (make_list_unique("/kb", cgi_dirs(port:port))) check_dir(path:dir);

exit(99);