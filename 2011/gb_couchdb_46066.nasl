###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_couchdb_46066.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Apache CouchDB Web Administration Interface Cross Site Scripting Vulnerability
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

tag_summary = "Apache CouchDB is prone to a cross-site scripting vulnerability
because it fails to properly sanitize user-supplied input.

An attacker may leverage this issue to execute arbitrary script code
in the browser of an unsuspecting user in the context of the affected
site. This may let the attacker steal cookie-based authentication
credentials and launch other attacks.

Apache CouchDB 0.8.0 up to and including 1.0.1 are vulnerable.";

tag_solution = "The vendor has released updates. Please see the references for
details.";

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.103053");
 script_version("$Revision: 9351 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2011-02-02 13:26:27 +0100 (Wed, 02 Feb 2011)");
 script_bugtraq_id(46066);
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2010-3854");

 script_name("Apache CouchDB Web Administration Interface Cross Site Scripting Vulnerability");

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/46066");
 script_xref(name : "URL" , value : "http://couchdb.apache.org/");

 script_tag(name:"qod_type", value:"remote_banner");
 script_category(ACT_GATHER_INFO);
 script_family("General");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("gb_couchdb_detect.nasl");
 script_require_ports("Services/www", 5984);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");

port = get_http_port(default:5984);
if(!get_port_state(port))exit(0);

if(!version = get_kb_item(string("couchdb/",port,"/version")))exit(0);
vers = version;

if(!isnull(vers) && vers >!< "unknown") {

  if(version_in_range(version:vers,test_version:"0.8.0",test_version2:"1.0.1")) {
    security_message(port:port);
    exit(0);
  }

}

exit(0);
