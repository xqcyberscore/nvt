# OpenVAS Vulnerability Test
# $Id: apache_log_injection.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: Apache Error Log Escape Sequence Injection
#
# Authors:
# George A. Theall, <theall@tifaware.com>.
#
# Copyright:
# Copyright (C) 2004 George A. Theall
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

tag_summary = "The target is running an Apache web server which allows for the
injection of arbitrary escape sequences into its error logs.  An
attacker might use this vulnerability in an attempt to exploit similar
vulnerabilities in terminal emulators. 

*****  OpenVAS has determined the vulnerability exists only by looking at
*****  the Server header returned by the web server running on the target.";

tag_solution = "Upgrade to Apache version 1.3.31 or 2.0.49 or newer.";
 
if (description) {
  script_oid("1.3.6.1.4.1.25623.1.0.12239");
  script_version("$Revision: 9348 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(9930);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
 script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_cve_id("CVE-2003-0020");
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2004-05-03");
  script_xref(name:"CLSA", value:"CLSA-2004:839");
  script_xref(name:"HPSB", value:"HPSBUX01022");
  script_xref(name:"RHSA", value:"RHSA-2003:139-07");
  script_xref(name:"RHSA", value:"RHSA-2003:243-07");
  script_xref(name:"MDKSA", value:"MDKSA-2003:050");
  script_xref(name:"OpenPKG-SA", value:"OpenPKG-SA-2004.021-apache");
  script_xref(name:"SSA", value:"SSA:2004-133-01");
  script_xref(name:"SuSE-SA", value:"SuSE-SA:2004:009");
  script_xref(name:"TLSA", value:"TLSA-2004-11");
  script_xref(name:"TSLSA", value:"TSLSA-2004-0017");

  name = "Apache Error Log Escape Sequence Injection";
  script_name(name);
 
  summary = "Checks for Apache Error Log Escape Sequence Injection Vulnerability";

  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2004 George A. Theall");

  family = "General";
  script_family(family);
  script_dependencies("global_settings.nasl", "http_version.nasl");
  script_require_keys("www/apache");
  script_require_ports("Services/www", 80);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}

include("global_settings.inc");
include("http_func.inc");

host = get_host_name();
port = get_http_port(default:80);
if (debug_level) display("debug: checking for Apache Error Log Escape Sequence Injection vulnerability on ", host, ":", port, ".\n");

# Check the web server's banner for the version.
banner = get_http_banner(port: port);
if (!banner) exit(0);

sig = strstr(banner, "Server:");
if (!sig) exit(0);
if (debug_level) display("debug: server sig = >>", sig, "<<.\n");

# For affected versions of Apache, see:
#   - http://www.apacheweek.com/features/security-13
#   - http://www.apacheweek.com/features/security-20
if(ereg(pattern:"^Server:.*Apache(-AdvancedExtranetServer)?/(1\.([0-2]\.[0-9]|3\.([0-9][^0-9]|[0-2][0-9]))|2\.0.([0-9][^0-9]|[0-3][0-9]|4[0-8]))", string:sig)) {
  security_message(port);
}
