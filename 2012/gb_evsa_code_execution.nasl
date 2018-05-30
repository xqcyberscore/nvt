###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_evsa_code_execution.nasl 10005 2018-05-29 13:54:41Z cfischer $
#
# ESVA (E-Mail Security Virtual Appliance) Remote Code Execution Vulnerability
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

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.103537");
 script_tag(name:"cvss_base", value:"9.4");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:N");
 script_version("$Revision: 10005 $");

 script_name("ESVA (E-Mail Security Virtual Appliance) Remote Code Execution Vulnerability");

 script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/20551/");

 script_tag(name:"last_modification", value:"$Date: 2018-05-29 15:54:41 +0200 (Tue, 29 May 2018) $");
 script_tag(name:"creation_date", value:"2012-08-16 14:33:49 +0200 (Thu, 16 Aug 2012)");
 script_category(ACT_ATTACK);
 script_tag(name:"qod_type", value:"remote_vul");
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");

 script_tag(name : "summary" , value : "ESVA (E-Mail Security Virtual Appliance) is prone to a remote code-execution vulnerability.");
 script_tag(name : "impact" , value : "Successful exploits will allow the attacker to execute arbitrary code within the context of
the application.");

 script_tag(name:"solution_type", value:"NoneAvailable");

 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

url = '/released.html';

if(http_vuln_check(port:port, url:url,pattern:"<title>--=.*- Message released from quarantine", usecache:TRUE)) {

  url = '/cgi-bin/learn-msg.cgi?id=|id;';

  if(http_vuln_check(port:port, url:url,pattern:"uid=[0-9]+.*gid=[0-9]+.*")) {
    security_message(port:port);
    exit(0);
  }
}

exit(0);
