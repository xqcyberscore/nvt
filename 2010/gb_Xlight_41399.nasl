###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_Xlight_41399.nasl 8266 2018-01-01 07:28:32Z teissa $
#
# Xlight FTP Server Multiple Directory Traversal Vulnerabilities
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

tag_summary = "Xlight FTP Server is prone to multiple directory-traversal
vulnerabilities because it fails to sufficiently sanitize user-
supplied input.

Exploiting these issues may allow an attacker to obtain sensitive
information which could aid in further attacks.

Xlight FTP Server 3.5.5 is vulnerable; other versions may also
be affected.";

tag_solution = "An update is available; please see the references for more
information.";

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.100708");
 script_version("$Revision: 8266 $");
 script_tag(name:"last_modification", value:"$Date: 2018-01-01 08:28:32 +0100 (Mon, 01 Jan 2018) $");
 script_tag(name:"creation_date", value:"2010-07-09 12:33:08 +0200 (Fri, 09 Jul 2010)");
 script_bugtraq_id(41399);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_name("Xlight FTP Server Multiple Directory Traversal Vulnerabilities");

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/41399");
 script_xref(name : "URL" , value : "http://www.xlightftpd.com/whatsnew.htm");
 script_xref(name : "URL" , value : "http://www.xlightftpd.com/index.htm");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/512192");

 script_tag(name:"qod_type", value:"remote_banner");
 script_category(ACT_GATHER_INFO);
 script_family("General");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("ssh_detect.nasl");
 script_require_ports("Services/ssh");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("ssh_func.inc");
include("version_func.inc");

port = get_kb_item("Services/ssh");
if(!port)exit(0);
if(!get_port_state(port))exit(0);

banner = get_kb_item("SSH/banner/" + port);
if(!banner)exit(0);
if("xlightftpd" >!< banner)exit(0);

version = eregmatch(pattern:"^SSH.*xlightftpd_(release_)?([0-9.]+)$", string:banner);
if(isnull(version[2]))exit(0);

if(version_is_equal(version:version[2], test_version:"3.5.5")) {

  security_message(port:port);
  exit(0);

}

exit(0);
