# OpenVAS Vulnerability Test
# $Id: phpgroupware_plaintext_cookie_auth_vuln.nasl 3359 2016-05-19 13:40:42Z antu123 $
# Description: PhpGroupWare plaintext cookie authentication credentials vulnerability
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

tag_summary = "The remote host seems to be running PhpGroupWare.

PhpGroupWare is a multi-user groupware suite written in PHP.

This version is reported to contain a plaintext cookie authentication 
credentials information disclosure vulnerability. If the web 
administration of PHPGroupWare is not conducted over an encrypted link, 
an attacker with the ability to sniff network traffic could easily 
retrieve these passwords. This may aid the attacker in further system 
compromise.";

tag_solution = "Update to version 0.9.16.002 or newer";

# Ref: PhpGroupWare Team

if(description)
{
 script_id(14293);
 script_version("$Revision: 3359 $");
 script_tag(name:"last_modification", value:"$Date: 2016-05-19 15:40:42 +0200 (Thu, 19 May 2016) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_cve_id("CVE-2004-2578");
 script_bugtraq_id(10895);
 script_xref(name:"OSVDB", value:"8354");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 name = "PhpGroupWare plaintext cookie authentication credentials vulnerability";

 script_name(name);
 
 summary = "Checks for PhpGroupWare version";
 
 script_summary(summary);
 
 script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
 
 
 script_copyright("This script is Copyright (C) 2004 David Maciejak");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("phpgroupware_detect.nasl");
 script_require_ports("Services/www", 80);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 script_xref(name : "URL" , value : "http://www.phpgroupware.org/");
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");

port = get_http_port(default:80);

kb = get_kb_item("www/" + port + "/phpGroupWare");
if ( ! kb ) exit(0);

matches = eregmatch(pattern:"(.*) under (.*)", string:kb);

if ( ereg(pattern:"^0\.([0-8]\.|9\.([0-9]\.|1[0-5]\.|16\.0*[01]([^0-9]|$)))", string:matches[1]) )
	security_message(port);
			
