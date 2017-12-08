# OpenVAS Vulnerability Test
# $Id: cvs_malformed_entry_lines_flaw.nasl 8023 2017-12-07 08:36:26Z teissa $
# Description: CVS malformed entry lines flaw
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
# based on work from (C) Tenable Network Security
#
# Copyright:
# Copyright (C) 2004 David Maciejak
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

tag_summary = "The remote CVS server, according to its version number, might allow an 
attacker to execute arbitrary commands on the remote system because of
a flaw relating to malformed Entry lines which lead to a
missing NULL terminator.

Among the issues deemed likely to be exploitable were:

- a double-free relating to the error_prog_name string (CVE-2004-0416)
- an argument integer overflow (CVE-2004-0417)
- out-of-bounds writes in serv_notify (CVE-2004-0418)";

tag_solution = "Upgrade to CVS 1.12.9 or 1.11.17";

# Ref:
#  Date: Wed, 9 Jun 2004 15:00:04 +0200
#  From: Stefan Esser <s.esser@e-matters.de>
#  To: full-disclosure@lists.netsys.com, bugtraq@securityfocus.com,
#        red@heisec.de, news@golem.de
#  Subject: Advisory 09/2004: More CVS remote vulnerabilities

if(description)
{
 script_id(12265);
 script_version("$Revision: 8023 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-07 09:36:26 +0100 (Thu, 07 Dec 2017) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_bugtraq_id(10499);
 script_cve_id("CVE-2004-0414","CVE-2004-0416","CVE-2004-0417","CVE-2004-0418"); 
 script_xref(name:"RHSA", value:"RHSA-2004:233-017");
 
 name = "CVS malformed entry lines flaw";
 script_name(name);
 


 
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
 
 script_copyright("This script is Copyright (C) 2004 David Maciejak");
 family = "General";
 script_family(family);
 script_require_ports("Services/cvspserver", 2401);
 script_dependencies("find_service.nasl", "cvspserver_version.nasl");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include('global_settings.inc');

port = get_kb_item("Services/cvspserver");
if(!port)port = 2401;
if(!get_port_state(port))exit(0);
version =  get_kb_item(string("cvs/", port, "/version"));
if ( ! version ) exit(0);
if(ereg(pattern:".* 1\.([0-9]\.|10\.|11\.([0-9][^0-9]|1[0-6])|12\.[0-8][^0-9]).*", string:version))
     	security_message(port);
