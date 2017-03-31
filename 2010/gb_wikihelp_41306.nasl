###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wikihelp_41306.nasl 5388 2017-02-21 15:13:30Z teissa $
#
# Wiki Web Help Cross Site Scripting and HTML Injection Vulnerabilities
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

tag_summary = "Wiki Web Help is prone to a cross-site scripting vulnerability and
multiple HTML-injection vulnerabilities because it fails to properly
sanitize user-supplied input before using it in dynamically
generated content.

Attacker-supplied HTML and script code could run in the context of the
affected browser, potentially allowing the attacker to steal cookie-
based authentication credentials or to control how the site is
rendered to the user. Other attacks are also possible.

Wiki Web Help 0.2.7 is vulnerable; other versions may also be
affected.";

tag_solution = "The vendor released a patch. Please see the references for more
information.";

if (description)
{
 script_id(100700);
 script_version("$Revision: 5388 $");
 script_tag(name:"last_modification", value:"$Date: 2017-02-21 16:13:30 +0100 (Tue, 21 Feb 2017) $");
 script_tag(name:"creation_date", value:"2010-07-06 13:44:35 +0200 (Tue, 06 Jul 2010)");
 script_bugtraq_id(41306);
 script_tag(name:"cvss_base", value:"2.6");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");
 script_name("Wiki Web Help Cross Site Scripting and HTML Injection Vulnerabilities");


 script_tag(name:"qod_type", value:"remote_vul");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/41306");
 script_xref(name : "URL" , value : "http://sourceforge.net/tracker/?func=detail&atid=1296085&aid=3025530&group_id=307693");
 script_xref(name : "URL" , value : "http://sourceforge.net/projects/wwh/");
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
   
  url = string(dir, "/revert.php?rev=%3Cscript%3Ealert(%27OpenVAS-XSS-Test%27)%3C/script%3E"); 

  if(http_vuln_check(port:port, url:url,pattern:"<script>alert\('OpenVAS-XSS-Test'\)</script>",check_header: TRUE, extra_check:"Revert to revision")) {
     
    security_message(port:port);
    exit(0);

  }
}

exit(0);

