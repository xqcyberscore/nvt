# OpenVAS Vulnerability Test
# $Id: cvstrac_output_formatter_dos.nasl 3854 2016-08-18 13:15:25Z teissa $
# Description: CVSTrac text output formatter DoS
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
#
# Copyright:
# Copyright (C) 2007 David Maciejak
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

tag_solution = "Upgrade to CVSTrac 2.0.1 or later.

CVSS Base Score : 4.3 (AV:N/AC:M/Au:N/C:N/I:N/A:P)";

tag_summary = "The remote web server contains a CGI script or is itself subject to a
denial of service attack. 

Description :

According to its version number, the version of CVSTrac installed on 
the remote host contains a flaw related to its Wiki-style text output 
formatter that may allow an attacker to cause a partial denial of service,
depending on the pages requested.";


if(description)
{
 script_id(80015);
 script_version("$Revision: 3854 $");
 script_tag(name:"last_modification", value:"$Date: 2016-08-18 15:15:25 +0200 (Thu, 18 Aug 2016) $");
 script_tag(name:"creation_date", value:"2008-10-24 19:51:47 +0200 (Fri, 24 Oct 2008)");
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
 script_tag(name:"qod_type", value:"remote_banner_unreliable");

 script_cve_id("CVE-2007-0347");
 script_bugtraq_id(22296);
 script_xref(name:"OSVDB", value:"31935");

 name = "CVSTrac text output formatter DoS";

 script_name(name);
 


 
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright("This script is Copyright (C) 2007 David Maciejak");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("cvstrac_detect.nasl");
 script_require_ports("Services/www", 80);
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name : "solution" , value : tag_solution);
 script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/458455/30/0/threaded");
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("http_func.inc");

port = get_http_port(default:80);
kb = get_kb_item("www/" + port + "/cvstrac" );
if ( ! kb ) exit(0);
stuff = eregmatch(pattern:"(.*) under (.*)", string:kb );
version = stuff[1]; 
if(ereg(pattern:"^([01]\.|2\.0\.0[^0-9.]?)", string:version))
	security_message(port);
