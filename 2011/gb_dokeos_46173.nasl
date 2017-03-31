###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dokeos_46173.nasl 3117 2016-04-19 10:19:37Z benallard $
#
# Dokeos Multiple Remote File Disclosure Vulnerabilities
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

tag_summary = "Dokeos and Chamilo are prone to multiple file-disclosure
vulnerabilities because they fail to properly sanitize user-
supplied input.

An attacker can exploit these vulnerabilities to view local files in
the context of the webserver process. This may aid in further attacks.

Dokeos versions 1.8.6.1 through 2.0 and Chamilo 1.8.7.1 are
vulnerable; other versions may also be affected.";

tag_solution = "Currently, we are not aware of any vendor-supplied patches. If you
feel we are in error or if you are aware of more recent information,
please mail us at: vuldb@securityfocus.com.";

if (description)
{
 script_id(103069);
 script_version("$Revision: 3117 $");
 script_tag(name:"last_modification", value:"$Date: 2016-04-19 12:19:37 +0200 (Tue, 19 Apr 2016) $");
 script_tag(name:"creation_date", value:"2011-02-08 13:20:01 +0100 (Tue, 08 Feb 2011)");
 script_bugtraq_id(46173);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

 script_name("Dokeos Multiple Remote File Disclosure Vulnerabilities");

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/46173");
 script_xref(name : "URL" , value : "http://www.chamilo.org");
 script_xref(name : "URL" , value : "http://code.google.com/p/chamilo/");
 script_xref(name : "URL" , value : "http://www.dokeos.com/");

 script_tag(name:"qod_type", value:"remote_banner");
 script_summary("Determine if installed dokeos version is vulnerable");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("dokeos_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

if (!can_host_php(port:port)) exit(0);

if(vers = get_version_from_kb(port:port,app:"dokeos")) {

  if(version_in_range(version: vers, test_version: "1.8.6.1",  test_version2:"2.0")) {
      security_message(port:port);
      exit(0);
  }

}

exit(0);
