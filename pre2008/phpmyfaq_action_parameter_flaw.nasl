# OpenVAS Vulnerability Test
# $Id: phpmyfaq_action_parameter_flaw.nasl 6053 2017-05-01 09:02:51Z teissa $
# Description: phpMyFAQ action parameter arbitrary file disclosure vulnerability
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
# based on work from (C) Tenable Network Security
#
# Copyright:
# Copyright (C) 2004 David Maciejak
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

tag_summary = "The remote web server contains a PHP script that permits information
disclosure of local files.

Description :

The version of phpMyFAQ on the remote host contains a flaw that may lead
to an unauthorized information disclosure.  The problem is that user
input passed to the 'action' parameter is not properly verified before
being used to include files, which could allow an remote attacker to
view any accessible file on the system, resulting in a loss of
confidentiality.";

tag_solution = "Upgrade to phpMyFAQ 1.3.13 or newer.";

# Ref: Stefan Esser <s.esser@e-matters.de>

if(description)
{
 script_id(14258);
 script_version("$Revision: 6053 $");
 script_tag(name:"last_modification", value:"$Date: 2017-05-01 11:02:51 +0200 (Mon, 01 May 2017) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_cve_id("CVE-2004-2255");
 script_bugtraq_id(10374);
 script_xref(name:"OSVDB", value:"6300");
 
 script_tag(name:"cvss_base", value:"6.4");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");

 name = "phpMyFAQ action parameter arbitrary file disclosure vulnerability";
 script_name(name);
 

 summary = "Check the version of phpMyFAQ";
 
 
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
 
 script_copyright("This script is Copyright (C) 2004 David Maciejak");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("phpmyfaq_detect.nasl");
 script_require_ports("Services/www", 80);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 script_xref(name : "URL" , value : "http://security.e-matters.de/advisories/052004.html");
 script_xref(name : "URL" , value : "http://www.phpmyfaq.de/advisory_2004-05-18.php");
 exit(0);
}

# Check starts here

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!get_port_state(port))
	exit(0);
if ( ! can_host_php(port:port) ) 
	exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/phpmyfaq"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];

  if (ver =~ "(0\.|1\.([0-2]\.|3\.([0-9]($|[^0-9])|1[0-2])))") security_message(port);
}
