###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_qianbo_enterprise_web_site_management_47375.nasl 3117 2016-04-19 10:19:37Z benallard $
#
# Qianbo Enterprise Web Site Management System 'Keyword' Parameter Cross Site Scripting Vulnerability
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

tag_summary = "Qianbo Enterprise Web Site Management System is prone to a cross-site
scripting vulnerability because it fails to sufficiently sanitize user-
supplied data.

An attacker may leverage this issue to execute arbitrary script code
in the browser of an unsuspecting user in the context of the affected
site. This may allow the attacker to steal cookie-based authentication
credentials and to launch other attacks.";


if (description)
{
 script_id(103150);
 script_version("$Revision: 3117 $");
 script_tag(name:"last_modification", value:"$Date: 2016-04-19 12:19:37 +0200 (Tue, 19 Apr 2016) $");
 script_tag(name:"creation_date", value:"2011-04-29 15:04:36 +0200 (Fri, 29 Apr 2011)");
 script_bugtraq_id(47375);
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
 script_name("Qianbo Enterprise Web Site Management System 'Keyword' Parameter Cross Site Scripting Vulnerability");

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/47375");
 script_xref(name : "URL" , value : "http://www.qianbo.com.cn/");

 script_tag(name:"qod_type", value:"remote_vul");
 script_summary("Determine if Qianbo Enterprise Web Site Management System is prone to a cross-site scripting vulnerability");
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
include("global_settings.inc");
   
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

if(!can_host_asp(port:port))exit(0);

dirs = make_list("/shop",cgi_dirs());

foreach dir (dirs) {
   
  url = string(dir,"/en/Search.Asp?Range=Product&Keyword=<script>alert(/openvas-xss-test/)</script>"); 

  if(http_vuln_check(port:port,url:url,pattern:"<script>alert\(/openvas-xss-test/\)</script>",check_header:TRUE,extra_check:make_list("Search","Products"))) {
     
    security_message(port:port);
    exit(0);

  }
}

exit(0);
