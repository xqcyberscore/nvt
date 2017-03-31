###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hp_power_manager_46830.nasl 3117 2016-04-19 10:19:37Z benallard $
#
# HP Power Manager Unspecified Cross Site Scripting Vulnerability
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

tag_summary = "The HP Power Manager is prone to an unspecified cross-site
scripting vulnerability because it fails to properly sanitize user-
supplied input.

An attacker may leverage this issue to execute arbitrary script code
in the browser of an unsuspecting user in the context of the affected
site. This may let the attacker steal cookie-based authentication
credentials and launch other attacks.";

tag_solution = "Vendor updates are available. Please see the references for
more details.";

if (description)
{
 script_id(103116);
 script_version("$Revision: 3117 $");
 script_tag(name:"last_modification", value:"$Date: 2016-04-19 12:19:37 +0200 (Tue, 19 Apr 2016) $");
 script_tag(name:"creation_date", value:"2011-03-11 13:29:22 +0100 (Fri, 11 Mar 2011)");
 script_bugtraq_id(46830);
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2011-0280");

 script_name("HP Power Manager Unspecified Cross Site Scripting Vulnerability");

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/46830");
 script_xref(name : "URL" , value : "http://www.hp.com");

 script_tag(name:"qod_type", value:"remote_banner");
 script_summary("Determine if installed HP Power Manager version is vulnerable");
 script_category(ACT_GATHER_INFO);
 script_family("General");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("hp_power_manager_detect.nasl");
 script_require_ports("Services/www", 80);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("version_func.inc");

port = get_http_port(default:80);

if(!get_port_state(port)){
  exit(0);
}

if(!vers = get_kb_item(string("www/", port, "/hp_power_manager"))){
  exit(0);
}

if(!isnull(vers) && vers >!< "unknown")
{
  if(version_is_less_equal(version:vers, test_version:"4.3.2")){
    security_message(port:port);
  }
}

