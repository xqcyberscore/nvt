###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_minalic_44393.nasl 14233 2019-03-16 13:32:43Z mmartin $
#
# MinaliC Directory Traversal and Denial of Service Vulnerabilities
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
  script_oid("1.3.6.1.4.1.25623.1.0.100872");
  script_version("$Revision: 14233 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-16 14:32:43 +0100 (Sat, 16 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-10-26 13:33:58 +0200 (Tue, 26 Oct 2010)");
  script_bugtraq_id(44393);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("MinaliC Directory Traversal and Denial of Service Vulnerabilities");

  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/44393");
  script_xref(name:"URL", value:"http://sourceforge.net/projects/minalic/");
  script_xref(name:"URL", value:"http://www.johnleitch.net/Vulnerabilities/MinaliC.Webserver.1.0.Directory.Traversal/53");
  script_xref(name:"URL", value:"http://www.johnleitch.net/Vulnerabilities/MinaliC.Webserver.1.0.Denial.Of.Service/52");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 8000);
  script_mandatory_keys("minaliC/banner");
  script_tag(name:"summary", value:"MinaliC is prone to a directory-traversal vulnerability and a denial-of-
service vulnerability.

Exploiting these issues will allow attackers to obtain sensitive
information or cause denial-of-service conditions.

MinaliC 1.0 is vulnerable. Other versions may also be affected.");
  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one.");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:8000);
if(!get_port_state(port))exit(0);

banner = get_http_banner(port:port);
if(!banner || "Server: minaliC" >!< banner)exit(0);

traversal = make_list(crap(data:"..%2f",length:7*5),crap(data:"..%5c",length:7*5));

foreach trav (traversal) {

  url = string(trav,"boot.ini");

  if(http_vuln_check(port:port, url:url,pattern:"\[boot loader\]")) {

    security_message(port:port);
    exit(0);

  }
}

exit(0);
