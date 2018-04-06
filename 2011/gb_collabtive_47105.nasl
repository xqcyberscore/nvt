###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_collabtive_47105.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Collabtive Multiple Remote Input Validation Vulnerabilities
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

tag_summary = "Collabtive is prone to multiple remote input-validation
vulnerabilities including cross-site scripting, HTML-injection, and
directory-traversal issues.

Attackers can exploit these issues to obtain sensitive information,
execute arbitrary script code, and steal cookie-based authentication
credentials.

Collabtive 0.6.5 is vulnerable; other versions may also be affected.";


if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.103138");
 script_version("$Revision: 9351 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2011-04-01 13:32:12 +0200 (Fri, 01 Apr 2011)");
 script_bugtraq_id(47105);
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

 script_name("Collabtive Multiple Remote Input Validation Vulnerabilities");

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/47105");
 script_xref(name : "URL" , value : "http://www.collabtive.com/");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/517267");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/517266");

 script_tag(name:"qod_type", value:"remote_banner");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("gb_collabtive_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("version_func.inc");

port = get_http_port(default:80);
if(!get_port_state(port)){
  exit(0);
}
if(!version = get_version_from_kb(port:port, app:"collabtive")){
  exit(0);
}

if(version_is_equal(version:version, test_version:"0.6.5")){
  security_message(port:port);
  exit(0);
}

exit(0);
