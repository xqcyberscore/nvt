###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_serv_u_44905.nasl 8266 2018-01-01 07:28:32Z teissa $
#
# Serv-U Empty Password Authentication Bypass Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
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

tag_summary = "Serv-U is prone to an authentication-bypass vulnerability.

Attackers can exploit this issue to gain unauthorized access to the
affected application. However, this requires that the application has
password-based authentication disabled.

Serv-U 10.2.0.2 and versions prior to 10.3.0.1 are vulnerable.";

tag_solution = "Updates are available. Please see the references for more information.";

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.100914");
 script_version("$Revision: 8266 $");
 script_tag(name:"last_modification", value:"$Date: 2018-01-01 08:28:32 +0100 (Mon, 01 Jan 2018) $");
 script_tag(name:"creation_date", value:"2010-11-25 12:46:25 +0100 (Thu, 25 Nov 2010)");
 script_bugtraq_id(44905);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_name("Serv-U Empty Password Authentication Bypass Vulnerability");

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/44905");
 script_xref(name : "URL" , value : "http://www.serv-u.com/");
 script_xref(name : "URL" , value : "http://www.serv-u.com/releasenotes/");

 script_tag(name:"qod_type", value:"remote_banner");
 script_category(ACT_GATHER_INFO);
 script_family("General");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("ssh_detect.nasl");
 script_require_ports("Services/ssh", 22);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("version_func.inc");

port = get_kb_item("Services/ssh");
if(!port) port = 22;

#banner = get_kb_item("SSH/banner/" + port);
banner ="SSH-2.0-Serv-U_10.3.0.1";
if(!banner || "Serv-U" >!< banner) exit(0);

version = eregmatch(pattern:"SSH-2.0-Serv-U_([0-9.]+)", string:banner);
if(!isnull(version[1])) {

  vers = split(version[1],sep:".",keep:FALSE);
  if(max_index(vers) < 4 && vers[0] >= 10 && (isnull(vers[1]) || vers[1] >= 3))exit(0);

  if(version_is_less(version:version[1],test_version:"10.3.0.1")) {
    security_message(port:port);
    exit(0);
  }  

}

exit(0);
