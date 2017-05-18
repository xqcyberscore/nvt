###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_zen_loadbalancer_55638.nasl 5963 2017-04-18 09:02:14Z teissa $
#
# ZEN Load Balancer Multiple Security Vulnerabilities
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

tag_summary = "ZEN Load Balancer is prone to the following security vulnerabilities:

1. Multiple arbitrary command-execution vulnerabilities
2. Multiple information-disclosure vulnerabilities
3. An arbitrary file-upload vulnerability

An attacker can exploit these issues to execute arbitrary commands,
upload arbitrary files to the affected computer, or disclose sensitive-
information.

ZEN Load Balancer 2.0 and 3.0 rc1 are vulnerable.";


SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103574";

if (description)
{
 script_oid(SCRIPT_OID);
 script_tag(name:"cvss_base", value:"9.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
 script_bugtraq_id(55638);
 script_version ("$Revision: 5963 $");

 script_name("ZEN Load Balancer Multiple Security Vulnerabilities");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/55638");

 script_tag(name:"last_modification", value:"$Date: 2017-04-18 11:02:14 +0200 (Tue, 18 Apr 2017) $");
 script_tag(name:"creation_date", value:"2012-09-24 10:00:04 +0200 (Mon, 24 Sep 2012)");
 script_category(ACT_ATTACK);
 script_tag(name:"qod_type", value:"remote_vul");
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
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
   
port = get_http_port(default:444);
if(!get_port_state(port))exit(0);

url = '/config/global.conf';

if(http_vuln_check(port:port, url:url,pattern:"Zen",extra_check:make_list("\$configdir","\$logdir"))) {
     
  security_message(port:port);
  exit(0);

}

exit(0);
