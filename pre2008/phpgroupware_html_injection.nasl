# OpenVAS Vulnerability Test
# $Id: phpgroupware_html_injection.nasl 3359 2016-05-19 13:40:42Z antu123 $
# Description: PhpGroupWare multiple HTML injection vulnerabilities
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

tag_summary = "The remote host seems to be running PhpGroupWare, is a multi-user groupware 
suite written in PHP.

This version has been reported prone to multiple HTML injection vulnerabilities. 
The issues present themselves due to a lack of sufficient input validation 
performed on form fields used by PHPGroupWare modules. 

A malicious attacker may inject arbitrary HTML and script code using these 
form fields that may be incorporated into dynamically generated web content.";

tag_solution = "Update to version 0.9.14.005 or newer";

# Ref: François SORIN <francois.sorin@security-corporation.com>

if(description)
{
 script_id(14292);
 script_version("$Revision: 3359 $");
 script_tag(name:"last_modification", value:"$Date: 2016-05-19 15:40:42 +0200 (Thu, 19 May 2016) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(8088);
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_cve_id("CVE-2003-0504");
 script_xref(name:"OSVDB", value:"2243");
 name = "PhpGroupWare multiple HTML injection vulnerabilities";

 script_name(name);
 
 summary = "Checks for PhpGroupWare version";
 
 script_summary(summary);
 
 script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_banner");
 
 
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
if ( ereg(pattern:"^0\.([0-8]\.|9\.([0-9]\.|1[0-3]\.|14\.0*[0-3]([^0-9]|$)))", string:matches[1]))
 			security_message(port);
