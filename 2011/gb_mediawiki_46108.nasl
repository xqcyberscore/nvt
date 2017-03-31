###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mediawiki_46108.nasl 3100 2016-04-18 14:41:20Z benallard $
#
# MediaWiki CSS Comments Cross Site Scripting Vulnerability
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

tag_summary = "MediaWiki is prone to a cross-site scripting vulnerability because it
fails to properly sanitize user-supplied input.

An attacker may leverage this issue to execute arbitrary script code
in the browser of an unsuspecting user in the context of the affected
site. This may let the attacker steal cookie-based authentication
credentials and launch other attacks.

Versions prior to MediaWiki 1.16.2 are vulnerable.";

tag_solution = "Updates are available. Please see the references for more information.";

if (description)
{
 script_id(103058);
 script_version("$Revision: 3100 $");
 script_tag(name:"last_modification", value:"$Date: 2016-04-18 16:41:20 +0200 (Mon, 18 Apr 2016) $");
 script_tag(name:"creation_date", value:"2011-02-03 13:07:13 +0100 (Thu, 03 Feb 2011)");
 script_bugtraq_id(46108);
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2011-0047");

 script_name("MediaWiki CSS Comments Cross Site Scripting Vulnerability");

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/46108");
 script_xref(name : "URL" , value : "http://lists.wikimedia.org/pipermail/mediawiki-announce/2011-February/000095.html");
 script_xref(name : "URL" , value : "http://wikipedia.sourceforge.net/");
 script_xref(name : "URL" , value : "https://bugzilla.wikimedia.org/show_bug.cgi?id=27093");

 script_tag(name:"qod_type", value:"remote_banner");
 script_summary("Determine if installed MediaWiki version is vulnerable");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("secpod_mediawiki_detect.nasl");
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

if(!vers = get_kb_item(string("MediaWiki/Version")))exit(0);

if(!isnull(vers) && vers >!< "unknown") {

  if(version_is_less(version: vers, test_version: "1.16.2")) {
      security_message(port:port);
      exit(0);
  }

}

exit(0);
