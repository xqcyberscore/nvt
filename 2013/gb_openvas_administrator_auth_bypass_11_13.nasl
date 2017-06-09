###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_openvas_administrator_auth_bypass_11_13.nasl 6125 2017-05-15 09:03:42Z teissa $
#
# OpenVAS Administrator Authentication Bypass
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

CPE = 'cpe:/a:openvas:openvas_administrator';
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103828";

tag_impact = "Attackers can exploit these issues to gain unauthorized access to the
affected application and perform certain actions.";

tag_insight = "A software bug in the server module 'OpenVAS Administrator' allowed to bypass the OAP
authentication procedure. The attack vector is remotely available in case public OAP is enabled.
In case of successful attack, the attacker gains partial rights to execute OAP commands.";

tag_summary = "The remote OpenVAS Administrator is prone to an authentication bypass.";

tag_solution = "Update to version 1.2.2 or 1.3.2.";
tag_vuldetect = "Try to bypass OAP authentication by sending a special crafted request.";

if (description)
{
 script_oid(SCRIPT_OID);
 script_version ("$Revision: 6125 $");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P"); 
 script_cve_id("CVE-2013-6766");
 script_name("OpenVAS Administrator Authentication Bypass");


 script_xref(name:"URL", value:"http://openvas.org/OVSA20131108.html");

 script_tag(name:"last_modification", value:"$Date: 2017-05-15 11:03:42 +0200 (Mon, 15 May 2017) $");
 script_tag(name:"creation_date", value:"2013-11-08 13:03:55 +0200 (Fri, 08 Nov 2013)");
 script_category(ACT_ATTACK);
 script_tag(name:"qod_type", value:"remote_vul");
 script_family("General");
 script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
 script_dependencies("gb_openvas_administrator_detect.nasl");
 script_mandatory_keys("openvas_administrator/installed");
 script_exclude_keys("greenbone/G_OS");

 script_tag(name : "impact" , value : tag_impact);
 script_tag(name : "vuldetect" , value : tag_vuldetect);
 script_tag(name : "insight" , value : tag_insight);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);

 exit(0);
}

include("host_details.inc");

if(get_kb_item("greenbone/G_OS"))exit(0); # there is an extra nvt for the gsm

if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);

soc = open_sock_tcp(port);
if(!soc)exit(0);

send(socket:soc, data:"<get_version/><get_users/>\r\n");
ret = recv(socket:soc, length: 1024); 

close(soc);

if("get_users_response status" >< ret && "<user>" >< ret) {

  security_message(port:port);
  exit(0);

}  

exit(99);
