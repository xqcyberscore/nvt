###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_InverseFlow_50344.nasl 3117 2016-04-19 10:19:37Z benallard $
#
# InverseFlow Multiple Cross Site Scripting Vulnerabilities
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

tag_summary = "InverseFlow is prone to multiple cross-site scripting
vulnerabilities because the application fails to sufficiently
sanitize user-supplied data.

An attacker could exploit these vulnerabilities to execute arbitrary
script code in the context of the affected website. This may allow the
attacker to steal cookie-based authentication credentials and launch
other attacks.

InverseFlow 2.4 is vulnerable; other versions may also be affected.";


if (description)
{
 script_id(103311);
 script_version("$Revision: 3117 $");
 script_tag(name:"last_modification", value:"$Date: 2016-04-19 12:19:37 +0200 (Tue, 19 Apr 2016) $");
 script_tag(name:"creation_date", value:"2011-10-25 14:02:26 +0200 (Tue, 25 Oct 2011)");
 script_bugtraq_id(50344);
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

 script_name("InverseFlow Multiple Cross Site Scripting Vulnerabilities");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/50344");
 script_xref(name : "URL" , value : "http://www.inverseflow.com/");

 script_tag(name:"qod_type", value:"remote_vul");
 script_summary("Determine if installed InverseFlow is vulnerable");
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
   
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

dirs = make_list("/inverseflow",cgi_dirs());

foreach dir (dirs) {
   
  url = string(dir,"/ticketview.php?email=%22%3E%3Cscript%3Ealert(/openvas-xss-test/)%3C/script%3E&id=1"); 

  if(http_vuln_check(port:port, url:url,pattern:"<script>alert\(/openvas-xss-test/\)</script>", check_header:TRUE)) {
     
    security_message(port:port);
    exit(0);

  }
}

exit(0);
