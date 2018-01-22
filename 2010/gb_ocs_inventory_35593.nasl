###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ocs_inventory_35593.nasl 8457 2018-01-18 07:58:32Z teissa $
#
# OCS Inventory NG Agent 'Backend.pm' Perl Module Handling Code Execution Vulnerability
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

tag_summary = "OCS Inventory NG Agent is prone to a vulnerability that lets local
attackers execute arbitrary Perl code.

Local attackers can leverage this issue to execute arbitrary code via
the application's insecure Perl module search path. This may allow
attackers to elevate their privileges and compromise the application
or the underlying computer. Other attacks may also be possible.";

tag_solution = "Updates are available. Please see the references for details.";

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.100868");
 script_version("$Revision: 8457 $");
 script_tag(name:"last_modification", value:"$Date: 2018-01-18 08:58:32 +0100 (Thu, 18 Jan 2018) $");
 script_tag(name:"creation_date", value:"2010-10-25 12:51:03 +0200 (Mon, 25 Oct 2010)");
 script_bugtraq_id(35593);
 script_cve_id("CVE-2009-0667");

 script_name("OCS Inventory NG Agent 'Backend.pm' Perl Module Handling Code Execution Vulnerability");


 script_tag(name:"cvss_base", value:"7.2");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"qod_type", value:"remote_banner");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("secpod_ocs_inventory_ng_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/35593");
 script_xref(name : "URL" , value : "http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=506416");
 script_xref(name : "URL" , value : "http://www.ocsinventory-ng.org/");
 script_xref(name : "URL" , value : "http://www.ocsinventory-ng.org/index.php?mact=News,cntnt01,detail,0&cntnt01articleid=144&cntnt01returnid=64");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

if(vers = get_version_from_kb(port:port,app:"OCS_Inventory_NG")) {

  if(version_is_equal(version: vers, test_version: "0.0.9.2") ||
     version_is_equal(version: vers, test_version: "1.00")) {
      security_message(port:port);
      exit(0);
  }

}

exit(0);
