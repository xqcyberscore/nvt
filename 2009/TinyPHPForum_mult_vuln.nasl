###############################################################################
# OpenVAS Vulnerability Test
# $Id: TinyPHPForum_mult_vuln.nasl 7573 2017-10-26 09:18:50Z cfischer $
#
# TinyPHPForum Multiple Vulnerabilities
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
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

tag_summary = "TinyPHPForum is prone to a directory-traversal vulnerability and to
  an authentication-bypass vulnerability because it fails to
  sufficiently sanitize user-supplied input data. A remote attacker
  can exploit this issue to perform administrative functions without
  requiring authentication or obtain sensitive information that could
  aid in further attacks.

  TinyPHPForum 3.6 and 3.6.1 are vulnerable;";


if (description)
{
 script_id(100097);
 script_version("$Revision: 7573 $");
 script_tag(name:"last_modification", value:"$Date: 2017-10-26 11:18:50 +0200 (Thu, 26 Oct 2017) $");
 script_tag(name:"creation_date", value:"2009-04-02 12:09:33 +0200 (Thu, 02 Apr 2009)");
 script_bugtraq_id(19281,34339);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

 script_name("TinyPHPForum Multiple Vulnerabilities");


 script_tag(name:"qod_type", value:"remote_banner");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("TinyPHPForum_detect.nasl");
 script_require_ports("Services/www", 80);
 script_tag(name : "summary" , value : tag_summary);
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/19281");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/34339");
 exit(0);
}


include("http_func.inc");
include("version_func.inc");

port = get_http_port(default:80);

if(VER = get_kb_item(string("www/", port, "/TinyPHPForum"))) {
  matches = eregmatch(string:VER, pattern:"^(.+) under (/.*)$");
  if(!isnull(matches)) {
    VER = matches[1];
    if(version_is_less_equal(version:VER, test_version:"3.6.1")) {
       security_message(port:port);
       exit(0);
    }   
  }
}

exit(0);
