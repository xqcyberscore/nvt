###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_syncrify_43333.nasl 8258 2017-12-29 07:28:57Z teissa $
#
# Syncrify Multiple Remote Security Bypass Vulnerabilities
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

tag_summary = "Syncrify is prone to multiple remote security-bypass vulnerabilities.

Exploiting these issues may allow a remote attacker to bypass certain
security restrictions and perform unauthorized actions.

Syncrify 2.1 Build 415 and prior are affected.";

tag_solution = "Updates are available. Please see the references for details.";

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.100820");
 script_version("$Revision: 8258 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-29 08:28:57 +0100 (Fri, 29 Dec 2017) $");
 script_tag(name:"creation_date", value:"2010-09-22 16:24:51 +0200 (Wed, 22 Sep 2010)");
 script_bugtraq_id(43333);

 script_name("Syncrify Multiple Remote Security Bypass Vulnerabilities");

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/43333");
 script_xref(name : "URL" , value : "http://web.synametrics.com/Syncrify.htm");
 script_xref(name : "URL" , value : "http://web.synametrics.com/SyncrifyVersionHistory.htm");

 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
 script_tag(name:"qod_type", value:"remote_banner");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("gb_syncrify_detect.nasl");
 script_require_ports("Services/www", 5800);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");

port = get_http_port(default:5800);
if(!get_port_state(port))exit(0);

if(vers = get_version_from_kb(port:port,app:"syncrify")) {

  if(version_is_less_equal(version: vers, test_version: "2.1.415")) {
      security_message(port:port);
      exit(0);
  }

}

exit(0);
