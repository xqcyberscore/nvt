# OpenVAS Vulnerability Test
# $Id: php_mail_func_header_spoof.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: PHP Mail Function Header Spoofing Vulnerability
#
# Authors:
# tony@libpcap.net, http://libpcap.net
#
# Copyright:
# Copyright (C) 2002 tony@libpcap.net
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

tag_summary = "The remote host is running a version of PHP <= 4.2.2.

The mail() function does not properly sanitize user input.
This allows users to forge email to make it look like it is
coming from a different source other than the server.

Users can exploit this even if SAFE_MODE is enabled.";

tag_solution = "Contact your vendor for the latest PHP release.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11444");
  script_version("$Revision: 9348 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(5562);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2002-0985", "CVE-2002-0986");

  name = "PHP Mail Function Header Spoofing Vulnerability";
  script_name(name);
 
  summary = "Checks for version of PHP";
 
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
 
  family = "Web application abuses";
  script_family(family);
  script_copyright("Copyright (C) 2002 tony@libpcap.net");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("PHP/banner");
  script_require_ports("Services/www", 80);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}

#
# The script code starts here
#

include("http_func.inc");

port = get_http_port(default:80);


if(get_port_state(port)) {
  banner = get_http_banner(port:port);
  if(!banner)exit(0);

  if(egrep(pattern:".*PHP/([0-3]\..*|4\.[0-1]\..*|4\.2\.[0-2][^0-9])", string:banner)) {
    security_message(port);
  }
}
 
