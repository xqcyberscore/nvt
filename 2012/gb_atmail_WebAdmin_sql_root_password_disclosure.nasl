###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_atmail_WebAdmin_sql_root_password_disclosure.nasl 5888 2017-04-07 09:01:53Z teissa $
#
# Atmail WebAdmin and Webmail Control Panel SQL Root Password Disclosure
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

tag_summary = "Atmail WebAdmin and Webmail Control Panel suffers from a SQL root password disclosure vulnerability.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103524";
CPE = "cpe:/a:atmail:atmail";

if (description)
{
 script_oid(SCRIPT_OID);
 script_bugtraq_id(54641);
 script_version ("$Revision: 5888 $");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_name("Atmail WebAdmin and Webmail Control Panel SQL Root Password Disclosure");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/54641");
 script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/114955/Atmail-WebAdmin-Webmail-Control-Panel-SQL-Root-Password-Disclosure.html");

 script_tag(name:"last_modification", value:"$Date: 2017-04-07 11:01:53 +0200 (Fri, 07 Apr 2017) $");
 script_tag(name:"creation_date", value:"2012-07-24 11:10:51 +0200 (Tue, 24 Jul 2012)");
 script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
 script_dependencies("atmail_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_mandatory_keys("Atmail/installed");
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("global_settings.inc");

if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);
if(!get_port_state(port))exit(0);

if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:port))exit(0);

url = dir + '/config/dbconfig.ini';

if(http_vuln_check(port:port, url:url,pattern:"database.adapter",extra_check:make_list("database.params.host","database.params.username","database.params.password"))) {
     
  security_message(port:port);
  exit(0);

}

exit(0);

