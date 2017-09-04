###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cms_made_simple_50659.nasl 7024 2017-08-30 11:51:43Z teissa $
#
# CMS Made Simple Remote Database Corruption Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
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

tag_summary = "CMS Made Simple is prone to a vulnerability that could result in the
corruption of the database.

An attacker can exploit this vulnerability to corrupt the database.

Versions prior to CMS Made Simple 1.9.4.3 are vulnerable.";

tag_solution = "Updates are available. Please see the references for more details.";

if (description)
{
 script_id(103332);
 script_bugtraq_id(50659);
 script_version ("$Revision: 7024 $");
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_name("CMS Made Simple Remote Database Corruption Vulnerability");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/50659");
 script_xref(name : "URL" , value : "http://www.cmsmadesimple.org/2011/08/Announcing-CMSMS-1-9-4-3---Security-Release/");
 script_xref(name : "URL" , value : "http://www.cmsmadesimple.org/");

 script_tag(name:"last_modification", value:"$Date: 2017-08-30 13:51:43 +0200 (Wed, 30 Aug 2017) $");
 script_tag(name:"creation_date", value:"2011-11-15 11:29:14 +0100 (Tue, 15 Nov 2011)");
 script_tag(name:"qod_type", value:"remote_banner");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("cms_made_simple_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("version_func.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

if (!can_host_php(port:port)) exit(0);

if(vers = get_version_from_kb(port:port,app:"cms_made_simple")) {

  if(version_is_less(version: vers, test_version: "1.9.4.3")) {
      security_message(port:port);
      exit(0);
  }

}

exit(0);
