###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_couchdb_42501.nasl 8457 2018-01-18 07:58:32Z teissa $
#
# Apache CouchDB Cross Site Request Forgery Vulnerability
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

tag_summary = "Apache CouchDB is prone to a cross-site request-forgery vulnerability.

Exploiting this issue may allow a remote attacker to gain unauthorized
access to the affected application and perform certain actions in the
context of the 'Futon' administration interface; other attacks are
also possible.

Versions prior to CouchDB 0.11.1 are vulnerable.";

tag_solution = "Updates are available. Please see the references for more information.";

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.100762");
 script_version("$Revision: 8457 $");
 script_tag(name:"last_modification", value:"$Date: 2018-01-18 08:58:32 +0100 (Thu, 18 Jan 2018) $");
 script_tag(name:"creation_date", value:"2010-08-30 14:30:07 +0200 (Mon, 30 Aug 2010)");
 script_bugtraq_id(42501);
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2010-2234");

 script_name("Apache CouchDB Cross Site Request Forgery Vulnerability");

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/42501");
 script_xref(name : "URL" , value : "http://couchdb.apache.org/downloads.html");
 script_xref(name : "URL" , value : "http://couchdb.apache.org/");
 script_xref(name : "URL" , value : "http://wiki.apache.org/couchdb/Breaking_changes");

 script_tag(name:"qod_type", value:"remote_banner");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
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
  if(version_is_less(version: vers, test_version: "0.11.1")) {
      security_message(port:port);
      exit(0);
  }
}

exit(0);

