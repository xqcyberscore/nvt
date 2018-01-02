###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_kerio_mailserver_40505.nasl 8250 2017-12-27 07:29:15Z teissa $
#
# Multiple Kerio Products Administration Console File Disclosure and Corruption Vulnerability
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

tag_summary = "Multiple Kerio Products are prone to a file disclosure and corruption
vulnerability.

An attacker can exploit this vulnerability to gain access to
files and corrupt data on a vulnerable computer. This may aid in
further attacks.

Kerio MailServer up to and including version 6.7.3 as well as
Kerio WinRoute Firewall up to and including version 6.7.1 patch2
are affected.";

tag_solution = "Updates are available. Please see the references for more information.";

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.100666");
 script_version("$Revision: 8250 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-27 08:29:15 +0100 (Wed, 27 Dec 2017) $");
 script_tag(name:"creation_date", value:"2010-06-03 13:39:07 +0200 (Thu, 03 Jun 2010)");
 script_bugtraq_id(40505);

 script_name("Multiple Kerio Products Administration Console File Disclosure and Corruption Vulnerability");

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/40505");
 script_xref(name : "URL" , value : "http://www.kerio.com");
 script_xref(name : "URL" , value : "http://www.kerio.com/support/security-advisories#1006");

 script_tag(name:"cvss_base", value:"4.4");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
 script_tag(name:"qod_type", value:"remote_banner");
 script_category(ACT_GATHER_INFO);
 script_family("SMTP problems");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("gb_kerio_mailserver_detect.nasl");
 script_require_ports("Services/smtp", 25);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("smtp_func.inc");
include("version_func.inc");

port = get_kb_item("Services/smtp");
if(!port) port = 25;

if(get_kb_item('SMTP/'+port+'/broken'))exit(0);
if(!get_port_state(port))exit(0);

if(!version = get_kb_item(string("KerioMailServer/Ver")))exit(0);

if(version_is_less_equal(version:version,test_version:"6.7.3")) {

  security_message(port:port);
  exit(0);
} 

exit(0);
