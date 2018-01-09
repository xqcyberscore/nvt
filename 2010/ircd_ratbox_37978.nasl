###############################################################################
# OpenVAS Vulnerability Test
# $Id: ircd_ratbox_37978.nasl 8314 2018-01-08 08:01:01Z teissa $
#
# IRCD-Hybrid and ircd-ratbox 'LINKS' Command Remote Integer Underflow Vulnerability
#
# Authors:
# Michael Meyer
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

tag_summary = "IRCD-Hybrid and ircd-ratbox are prone to a remote integer-underflow
vulnerability.

A remote attacker may exploit this issue to execute arbitrary code
within the context of the affected application. Failed exploit
attempts will likely crash the application, denying service to
legitimate users.

IRCD-Hybrid 7.2.2 and ircd-ratbox 2.2.8 are vulnerable; other versions
may also be affected.";

tag_solution = "Updates are available. Please see the references for details.";

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.100472");
 script_version("$Revision: 8314 $");
 script_tag(name:"last_modification", value:"$Date: 2018-01-08 09:01:01 +0100 (Mon, 08 Jan 2018) $");
 script_tag(name:"creation_date", value:"2010-01-28 18:48:47 +0100 (Thu, 28 Jan 2010)");
 script_bugtraq_id(37978);
 script_cve_id("CVE-2009-4016");
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

 script_name("IRCD-Hybrid and ircd-ratbox 'LINKS' Command Remote Integer Underflow Vulnerability");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/37978");
 script_xref(name : "URL" , value : "http://www.ircd-hybrid.org/");
 script_xref(name : "URL" , value : "http://www.ircd-ratbox.org/");

 script_tag(name:"qod_type", value:"remote_banner");
 script_category(ACT_GATHER_INFO);
 script_family("General");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("ircd.nasl");
 script_require_ports("Services/irc", 6667);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("version_func.inc");

port = get_kb_item("Services/irc");
if(!port)port = 6667;
if(! get_port_state(port)) exit(0);

banner = get_kb_item(string("irc/banner/", port));
if(!banner)exit(0);
if("ratbox" >!< banner)exit(0);

version = eregmatch(pattern:"ircd-ratbox-([0-9.]+)", string: banner);
if(isnull(version[1]))exit(0);

if(version_is_less_equal(version: version[1], test_version: "2.2.8"))
{
  security_message(port:port);
  exit(0);
}


