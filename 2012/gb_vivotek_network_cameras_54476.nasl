###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vivotek_network_cameras_54476.nasl 5950 2017-04-13 09:02:06Z teissa $
#
# Vivotek Network Cameras Information Disclosure Vulnerability
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

tag_summary = "Vivotek Network Cameras are prone to an information-disclosure
vulnerability.

Successful exploits will allow a remote attacker to gain access
to sensitive information. Information obtained will aid in
further attacks.";


SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103521";

if (description)
{
 script_oid(SCRIPT_OID);
 script_bugtraq_id(54476);
 script_version ("$Revision: 5950 $");
 script_cve_id("CVE-2013-1594", "CVE-2013-1595", "CVE-2013-1596", "CVE-2013-1597",
               "CVE-2013-1598");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_name("Vivotek Network Cameras Information Disclosure Vulnerability");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/54476");

 script_tag(name:"last_modification", value:"$Date: 2017-04-13 11:02:06 +0200 (Thu, 13 Apr 2017) $");
 script_tag(name:"creation_date", value:"2012-07-17 14:10:13 +0200 (Tue, 17 Jul 2012)");
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
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

url = '/cgi-bin/admin/getparam.cgi';

if(http_vuln_check(port:port, url:url,pattern:"system_hostname")) {
 
  security_message(port:port);
  exit(0);

}

exit(0);
