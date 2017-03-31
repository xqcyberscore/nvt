###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_novell_groupwise_54253.nasl 3062 2016-04-14 11:03:39Z benallard $
#
# Novell Groupwise WebAccess 'User.interface' Parameter Directory Traversal Vulnerability
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

tag_summary = "Groupwise is prone to a directory-traversal vulnerability because it
fails to properly sanitize user-supplied input.

Remote attackers can use specially crafted requests with directory-
traversal sequences ('../') to retrieve arbitrary files in the context
of the application.

Exploiting this issue may allow an attacker to obtain sensitive
information that could aid in further attacks.

Groupwise versions 8.0x through 8.02 HP3 are affected.";

tag_solution = "Vendor updates are available. Please see the references for more
information.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103519";

if (description)
{
 script_oid(SCRIPT_OID);
 script_bugtraq_id(54253);
 script_cve_id("CVE-2012-0410");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_version ("$Revision: 3062 $");

 script_name("Novell Groupwise WebAccess 'User.interface' Parameter Directory Traversal Vulnerability");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/54253");
 script_xref(name : "URL" , value : "http://www.novell.com/groupwise/");

 script_tag(name:"last_modification", value:"$Date: 2016-04-14 13:03:39 +0200 (Thu, 14 Apr 2016) $");
 script_tag(name:"creation_date", value:"2012-07-16 12:02:03 +0200 (Mon, 16 Jul 2012)");
 script_summary("Determine if directory traversal is possible");
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

dirs = make_list("/gw","/servlet",cgi_dirs());

foreach dir (dirs) {
   
  url = dir + '/webacc?User.interface=/../webacc/wml'; 

  if(http_vuln_check(port:port, url:url,pattern:"<wml>", extra_check:make_list("<template>","Novell GroupWise","<onevent"))) {
     
    security_message(port:port);
    exit(0);

  }
}

exit(0);

