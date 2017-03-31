###############################################################################
# OpenVAS Vulnerability Test
# $Id: bugzilla_37062.nasl 4574 2016-11-18 13:36:58Z teissa $
#
# Bugzilla Bug Alias Information Disclosure Vulnerability
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

tag_summary = "Bugzilla is prone to an information-disclosure vulnerability.

The issue may allow attackers to obtain potentially sensitive
information that may aid in other attacks.

The issue affects the following:

Bugzilla 3.3.2 through 3.4.3 Bugzilla 3.5 through 3.5.1";


tag_solution = "Updates are available. Please see the references for details.";

if (description)
{
 script_id(100358);
 script_version("$Revision: 4574 $");
 script_tag(name:"last_modification", value:"$Date: 2016-11-18 14:36:58 +0100 (Fri, 18 Nov 2016) $");
 script_tag(name:"creation_date", value:"2009-11-20 12:35:38 +0100 (Fri, 20 Nov 2009)");
 script_cve_id("CVE-2009-3386");
 script_bugtraq_id(37062);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

 script_name("Bugzilla Bug Alias Information Disclosure Vulnerability");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/37062");
 script_xref(name : "URL" , value : "http://www.bugzilla.org");
 script_xref(name : "URL" , value : "http://www.bugzilla.org/security/3.4.3/");

 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("bugzilla_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("version_func.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

if (!can_host_php(port:port)) exit(0);

if(!version = get_kb_item(string("www/", port, "/bugzilla/version")))exit(0);

if(!isnull(version) && version >!< "unknown") {

  if(version =~ "3\.5") {
    if(version_is_less(version: version, test_version: "3.5.2 ")) {
     security_message(port:port);
     exit(0);
    }  
  }
  else if(version =~ "3\.(3|4)") { 
    if(version_in_range(version: version, test_version: "3.3.2", test_version2: "3.4.3")) {
     security_message(port:port);
     exit(0);
    }  
  }  
}

exit(0);
