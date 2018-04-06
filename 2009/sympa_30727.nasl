###############################################################################
# OpenVAS Vulnerability Test
# $Id: sympa_30727.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Sympa 'sympa.pl' Insecure Temporary File Creation Vulnerability
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

tag_summary = "Sympa creates temporary files in an insecure manner.

An attacker with local access could potentially exploit this issue to
perform symbolic-link attacks, overwriting arbitrary files in the
context of the affected application.

Successfully mounting a symlink attack may allow the attacker to
delete or corrupt sensitive files, which may result in a denial of
service. Other attacks may also be possible.

Sympa 5.4.3 is vulnerable; other versions may also be affected.";

tag_solution = "Updates are available. Please see the references for more information.";

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.100299");
 script_version("$Revision: 9350 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2009-10-11 19:51:15 +0200 (Sun, 11 Oct 2009)");
 script_bugtraq_id(30727);
 script_cve_id("CVE-2008-4476");
 script_tag(name:"cvss_base", value:"6.9");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");

 script_name("Sympa 'sympa.pl' Insecure Temporary File Creation Vulnerability");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/30727");
 script_xref(name : "URL" , value : "http://www.sympa.org/");
 script_xref(name : "URL" , value : "http://www.sympa.org/distribution/");
 script_xref(name : "URL" , value : "http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=494969");

 script_tag(name:"qod_type", value:"remote_banner");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("sympa_detect.nasl");
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

if(!version = get_kb_item(string("www/", port, "/sympa")))exit(0);
if(!matches = eregmatch(string:version, pattern:"^(.+) under (/.*)$"))exit(0);

vers = matches[1];

if(!isnull(vers) && vers >!< "unknown") {

  if(version_is_equal(version: vers, test_version: "5.4.3")) {
      security_message(port:port);
      exit(0);
  }

}

exit(0);
