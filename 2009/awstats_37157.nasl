###############################################################################
# OpenVAS Vulnerability Test
# $Id: awstats_37157.nasl 4574 2016-11-18 13:36:58Z teissa $
#
# AWStats Multiple Unspecified Security Vulnerabilities
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

tag_summary = "AWStats is prone to multiple security vulnerabilities.

Very few details are available. We will update this BID as more
information emerges.

The impact of these issues has not been disclosed.";


tag_solution = "Updates are available. Please see the references for details.";

if (description)
{
 script_id(100380);
 script_version("$Revision: 4574 $");
 script_tag(name:"last_modification", value:"$Date: 2016-11-18 14:36:58 +0100 (Fri, 18 Nov 2016) $");
 script_tag(name:"creation_date", value:"2009-12-08 22:02:24 +0100 (Tue, 08 Dec 2009)");
 script_bugtraq_id(37157);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

 script_name("AWStats Multiple Unspecified Security Vulnerabilities");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/37157");
 script_xref(name : "URL" , value : "http://awstats.sourceforge.net/docs/awstats_changelog.txt");
 script_xref(name : "URL" , value : "http://awstats.sourceforge.net/");

 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("awstats_detect.nasl");
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

if(!version = get_kb_item(string("www/", port, "/awstats")))exit(0);
if(!matches = eregmatch(string:version, pattern:"^(.+) under (/.*)$"))exit(0);

vers = matches[1];

if(!isnull(vers) && vers >!< "unknown") {

  if(version_is_less(version: vers, test_version: "6.95")) {
      security_message(port:port);
      exit(0);
  }

}

exit(0);
