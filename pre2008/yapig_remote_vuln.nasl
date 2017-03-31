# OpenVAS Vulnerability Test
# $Id: yapig_remote_vuln.nasl 3359 2016-05-19 13:40:42Z antu123 $
# Description: YaPiG Remote Server-Side Script Execution Vulnerability
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
# based on work from (C) Tenable Network Security
#
# Copyright:
# Copyright (C) 2004 David Maciejak
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
arbitrary PHP code injection vulnerabilities. 

Description :

The remote host is running YaPiG, a web-based image gallery written in
PHP. 

The remote version of YaPiG may allow a remote attacker to execute
malicious scripts on a vulnerable system.  This issue exists due to a
lack of sanitization of user-supplied data.  It is reported that an
attacker may be able to upload content that will be saved on the
server with a '.php' extension.  When this file is requested by the
attacker, the contents of the file will be parsed and executed by the
PHP engine, rather than being sent.  Successful exploitation of this
issue may allow an attacker to execute malicious script code on a
vulnerable server.";

tag_solution = "Upgrade to YaPiG 0.92.2 or later.";

#  Ref: aCiDBiTS <acidbits@hotmail.com>

if(description)
{
 script_id(14269);
 script_version("$Revision: 3359 $");
 script_tag(name:"last_modification", value:"$Date: 2016-05-19 15:40:42 +0200 (Thu, 19 May 2016) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(10891);
 script_xref(name:"OSVDB", value:"8657");
 script_xref(name:"OSVDB", value:"8658");
 script_tag(name:"cvss_base", value:"5.8");
 script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:P/I:P/A:P");
 name = "YaPiG Remote Server-Side Script Execution Vulnerability";

 script_name(name);
 
 summary = "Checks for YaPiG version";
 
 script_summary(summary);
 
 script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_banner");
 
 
 script_copyright("This script is Copyright (C) 2004 David Maciejak");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 script_xref(name : "URL" , value : "http://archives.neohapsis.com/archives/fulldisclosure/2004-08/0756.html");
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");


port = get_http_port(default:80);
if(!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


dirs = make_list("/yapig", "/gallery", "/photos", "/photo", cgi_dirs());

foreach dir (dirs)
{
	res = http_get_cache(item:string(dir, "/"), port:port);
	if (res == NULL) exit(0);

	#Powered by <a href="http://yapig.sourceforge.net" title="Yet Another PHP Image Gallery">YaPig</a> V0.92b
 	if(egrep(pattern:"Powered by .*YaPig.* V0\.([0-8][0-9][^0-9]|9([01]|2[ab]))", string:res))
 	{
 		security_message(port);
		exit(0);
	}
 
}
